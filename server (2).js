// ============================================================
// AUX WORKFORCE MANAGEMENT SYSTEM — Backend (Node.js + Express)
// File: server.js  |  Run: node server.js
// ============================================================
// Install: npm install express pg bcryptjs jsonwebtoken dotenv cors

const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

// ── DB CONNECTION ──────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL, // From .env
  ssl: { rejectUnauthorized: false }           // Required for Neon/Render
});

// ── JWT MIDDLEWARE ─────────────────────────────────────────
const auth = (roles = []) => (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (roles.length && !roles.includes(decoded.role)) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    req.user = decoded;
    next();
  } catch { res.status(401).json({ error: 'Invalid token' }); }
};

// Determine if login is late
function isLate(loginTime, shiftStart, graceMins) {
  const deadline = new Date(loginTime);
  deadline.setHours(shiftStart.getHours(), shiftStart.getMinutes() + graceMins, 0);
  return loginTime > deadline;
}

// ────────────────────────────────────────────────────────────
// AUTH ROUTES
// ────────────────────────────────────────────────────────────

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query(
      `SELECT u.*, r.role_name FROM users u
       JOIN roles r ON u.role_id = r.id
       WHERE u.email = $1 AND u.status = 'ACTIVE'`, [email]
    );
    const user = result.rows[0];
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign(
      { id: user.id, employee_id: user.employee_id, role: user.role_name, name: user.full_name },
      process.env.JWT_SECRET, { expiresIn: '12h' }
    );
    res.json({ token, role: user.role_name, name: user.full_name, employee_id: user.employee_id });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// POST /api/auth/otp-login (Send OTP)
app.post('/api/auth/send-otp', async (req, res) => {
  const { phone } = req.body;
  const otp = Math.floor(1000 + Math.random() * 9000).toString();
  // TODO: Integrate with SMS provider (Twilio/MSG91)
  // For demo: store OTP in DB or cache, return in response (REMOVE IN PRODUCTION)
  console.log(`OTP for ${phone}: ${otp}`);
  res.json({ message: 'OTP sent', otp }); // Remove otp from response in prod
});

// POST /api/auth/verify-otp
app.post('/api/auth/verify-otp', async (req, res) => {
  const { phone, otp } = req.body;
  // TODO: Verify OTP from DB/cache
  if (otp !== '1234') return res.status(400).json({ error: 'Invalid OTP' }); // demo only
  const result = await pool.query(
    `SELECT u.*, r.role_name FROM users u JOIN roles r ON u.role_id = r.id WHERE u.phone = $1`, [phone]
  );
  if (!result.rows[0]) return res.status(404).json({ error: 'User not found' });
  const user = result.rows[0];
  const token = jwt.sign(
    { id: user.id, employee_id: user.employee_id, role: user.role_name, name: user.full_name },
    process.env.JWT_SECRET, { expiresIn: '12h' }
  );
  res.json({ token, role: user.role_name, name: user.full_name });
});

// ────────────────────────────────────────────────────────────
// ATTENDANCE ROUTES
// ────────────────────────────────────────────────────────────

// POST /api/attendance/login
app.post('/api/attendance/login', auth(['EMPLOYEE', 'TEAM_LEAD']), async (req, res) => {
  const userId = req.user.id;
  const loginTime = new Date();
  try {
    // Check if already logged in today
    const existing = await pool.query(
      `SELECT id FROM attendance_sessions WHERE user_id=$1 AND DATE(login_time)=CURRENT_DATE`, [userId]
    );
    if (existing.rows.length) return res.status(400).json({ error: 'Already logged in today' });

    // Get shift for late check
    const shiftRes = await pool.query(
      `SELECT s.start_time, s.grace_minutes FROM shift_assignments sa
       JOIN shifts s ON sa.shift_id = s.id
       WHERE sa.user_id=$1 AND sa.start_date <= CURRENT_DATE
       AND (sa.end_date IS NULL OR sa.end_date >= CURRENT_DATE)
       ORDER BY sa.start_date DESC LIMIT 1`, [userId]
    );
    let late = false;
    if (shiftRes.rows[0]) {
      const [h, m] = shiftRes.rows[0].start_time.split(':').map(Number);
      const shiftStart = new Date(); shiftStart.setHours(h, m, 0);
      late = isLate(loginTime, shiftStart, shiftRes.rows[0].grace_minutes);
    }

    const result = await pool.query(
      `INSERT INTO attendance_sessions (user_id, login_time, late_login, status)
       VALUES ($1, $2, $3, 'PRESENT') RETURNING id`, [userId, loginTime, late]
    );
    res.json({ session_id: result.rows[0].id, login_time: loginTime, late_login: late });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// POST /api/attendance/logout
app.post('/api/attendance/logout', auth(['EMPLOYEE', 'TEAM_LEAD']), async (req, res) => {
  const userId = req.user.id;
  try {
    const session = await pool.query(
      `SELECT id, login_time FROM attendance_sessions WHERE user_id=$1 AND DATE(login_time)=CURRENT_DATE AND logout_time IS NULL`, [userId]
    );
    if (!session.rows[0]) return res.status(400).json({ error: 'No active session' });
    const sessionId = session.rows[0].id;
    const logoutTime = new Date();
    const totalMins = Math.floor((logoutTime - new Date(session.rows[0].login_time)) / 60000);

    // Get total break/lunch/meeting minutes
    const eventsRes = await pool.query(
      `SELECT COALESCE(SUM(duration_minutes), 0) as total_break FROM attendance_events
       WHERE session_id=$1 AND end_time IS NOT NULL`, [sessionId]
    );
    const workMins = totalMins - parseInt(eventsRes.rows[0].total_break);
    const status = workMins < 240 ? 'HALF_DAY' : 'PRESENT';

    await pool.query(
      `UPDATE attendance_sessions SET logout_time=$1, total_work_minutes=$2, status=$3 WHERE id=$4`,
      [logoutTime, workMins, status, sessionId]
    );
    res.json({ logout_time: logoutTime, total_work_minutes: workMins, status });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Generic event start/end helper
async function startEvent(req, res, eventType) {
  const userId = req.user.id;
  try {
    const session = await pool.query(
      `SELECT id FROM attendance_sessions WHERE user_id=$1 AND DATE(login_time)=CURRENT_DATE AND logout_time IS NULL`, [userId]
    );
    if (!session.rows[0]) return res.status(400).json({ error: 'Not logged in' });
    // Check no open event of same type
    const open = await pool.query(
      `SELECT id FROM attendance_events WHERE session_id=$1 AND event_type=$2 AND end_time IS NULL`,
      [session.rows[0].id, eventType]
    );
    if (open.rows.length) return res.status(400).json({ error: eventType + ' already started' });
    const result = await pool.query(
      `INSERT INTO attendance_events (session_id, event_type, start_time) VALUES ($1,$2,$3) RETURNING id`,
      [session.rows[0].id, eventType, new Date()]
    );
    res.json({ event_id: result.rows[0].id, started_at: new Date() });
  } catch (e) { res.status(500).json({ error: e.message }); }
}

async function endEvent(req, res, eventType) {
  const userId = req.user.id;
  try {
    const session = await pool.query(
      `SELECT id FROM attendance_sessions WHERE user_id=$1 AND DATE(login_time)=CURRENT_DATE AND logout_time IS NULL`, [userId]
    );
    if (!session.rows[0]) return res.status(400).json({ error: 'Not logged in' });
    const event = await pool.query(
      `SELECT id, start_time FROM attendance_events WHERE session_id=$1 AND event_type=$2 AND end_time IS NULL`,
      [session.rows[0].id, eventType]
    );
    if (!event.rows[0]) return res.status(400).json({ error: eventType + ' not started' });
    const endTime = new Date();
    const duration = Math.floor((endTime - new Date(event.rows[0].start_time)) / 60000);
    await pool.query(
      `UPDATE attendance_events SET end_time=$1, duration_minutes=$2 WHERE id=$3`,
      [endTime, duration, event.rows[0].id]
    );
    res.json({ duration_minutes: duration, ended_at: endTime });
  } catch (e) { res.status(500).json({ error: e.message }); }
}

app.post('/api/attendance/break/start',   auth(), (req, res) => startEvent(req, res, 'BREAK'));
app.post('/api/attendance/break/end',     auth(), (req, res) => endEvent(req, res, 'BREAK'));
app.post('/api/attendance/lunch/start',   auth(), (req, res) => startEvent(req, res, 'LUNCH'));
app.post('/api/attendance/lunch/end',     auth(), (req, res) => endEvent(req, res, 'LUNCH'));
app.post('/api/attendance/meeting/start', auth(), (req, res) => startEvent(req, res, 'MEETING'));
app.post('/api/attendance/meeting/end',   auth(), (req, res) => endEvent(req, res, 'MEETING'));

// ────────────────────────────────────────────────────────────
// LEAVE ROUTES
// ────────────────────────────────────────────────────────────

// POST /api/leave/apply
app.post('/api/leave/apply', auth(['EMPLOYEE', 'TEAM_LEAD']), async (req, res) => {
  const { leave_type, start_date, end_date, reason } = req.body;
  const userId = req.user.id;
  try {
    // Validate: Must apply 2 days before
    const fromDate = new Date(start_date);
    const today = new Date(); today.setHours(0,0,0,0);
    const diffDays = Math.floor((fromDate - today) / 86400000);
    if (diffDays < 2) return res.status(400).json({ error: 'Leave must be applied at least 2 days in advance' });

    // Check slot availability
    const slot = await pool.query(
      `SELECT booked_slots, max_slots FROM leave_slots WHERE leave_date = $1`, [start_date]
    );
    if (slot.rows[0] && slot.rows[0].booked_slots >= slot.rows[0].max_slots) {
      return res.status(400).json({ error: 'Leave slot already booked for this date' });
    }

    // Check balance
    const balCol = leave_type === 'CASUAL' ? 'casual_leave' : leave_type === 'SICK' ? 'sick_leave' : 'earned_leave';
    const leaveDays = Math.floor((new Date(end_date) - fromDate) / 86400000) + 1;
    const balance = await pool.query(`SELECT ${balCol} FROM leave_balances WHERE user_id=$1`, [userId]);
    if (!balance.rows[0] || balance.rows[0][balCol] < leaveDays) {
      return res.status(400).json({ error: 'Insufficient leave balance' });
    }

    // Insert leave request
    const result = await pool.query(
      `INSERT INTO leave_requests (user_id, leave_type, start_date, end_date, reason)
       VALUES ($1, $2, $3, $4, $5) RETURNING id`,
      [userId, leave_type, start_date, end_date, reason]
    );

    // Update slot
    await pool.query(
      `INSERT INTO leave_slots (leave_date, max_slots, booked_slots) VALUES ($1, 1, 1)
       ON CONFLICT (leave_date) DO UPDATE SET booked_slots = leave_slots.booked_slots + 1`, [start_date]
    );

    res.json({ message: 'Leave applied successfully', request_id: result.rows[0].id });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// PUT /api/leave/approve/:id
app.put('/api/leave/approve/:id', auth(['TEAM_LEAD', 'ADMIN', 'HR']), async (req, res) => {
  try {
    const leave = await pool.query(`SELECT * FROM leave_requests WHERE id=$1`, [req.params.id]);
    if (!leave.rows[0]) return res.status(404).json({ error: 'Leave not found' });
    if (leave.rows[0].approval_status !== 'PENDING') return res.status(400).json({ error: 'Already processed' });

    await pool.query(
      `UPDATE leave_requests SET approval_status='APPROVED', approved_by=$1, updated_at=NOW() WHERE id=$2`,
      [req.user.id, req.params.id]
    );
    // Deduct leave balance
    const { user_id, leave_type, start_date, end_date } = leave.rows[0];
    const days = Math.floor((new Date(end_date) - new Date(start_date)) / 86400000) + 1;
    const col = leave_type === 'CASUAL' ? 'casual_leave' : leave_type === 'SICK' ? 'sick_leave' : 'earned_leave';
    await pool.query(`UPDATE leave_balances SET ${col} = ${col} - $1 WHERE user_id = $2`, [days, user_id]);
    // Notify employee
    await pool.query(`INSERT INTO notifications (user_id, title, message) VALUES ($1, $2, $3)`,
      [user_id, 'Leave Approved ✅', `Your ${leave_type} leave from ${start_date} to ${end_date} has been approved.`]);
    res.json({ message: 'Leave approved' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// PUT /api/leave/reject/:id
app.put('/api/leave/reject/:id', auth(['TEAM_LEAD', 'ADMIN', 'HR']), async (req, res) => {
  try {
    await pool.query(
      `UPDATE leave_requests SET approval_status='REJECTED', approved_by=$1, updated_at=NOW() WHERE id=$2`,
      [req.user.id, req.params.id]
    );
    // Free up the slot
    const leave = await pool.query(`SELECT start_date, user_id FROM leave_requests WHERE id=$1`, [req.params.id]);
    if (leave.rows[0]) {
      await pool.query(`UPDATE leave_slots SET booked_slots = GREATEST(0, booked_slots - 1) WHERE leave_date=$1`,
        [leave.rows[0].start_date]);
      await pool.query(`INSERT INTO notifications (user_id, title, message) VALUES ($1, $2, $3)`,
        [leave.rows[0].user_id, 'Leave Rejected ❌', `Your leave request has been rejected. Please contact HR for details.`]);
    }
    res.json({ message: 'Leave rejected' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// GET /api/leave/calendar
app.get('/api/leave/calendar', auth(), async (req, res) => {
  try {
    const slots = await pool.query(
      `SELECT leave_date, max_slots, booked_slots,
              CASE WHEN booked_slots >= max_slots THEN FALSE ELSE TRUE END as available
       FROM leave_slots WHERE leave_date >= CURRENT_DATE ORDER BY leave_date`
    );
    res.json(slots.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ────────────────────────────────────────────────────────────
// DASHBOARD ROUTES
// ────────────────────────────────────────────────────────────

// GET /api/dashboard/employee
app.get('/api/dashboard/employee', auth(['EMPLOYEE']), async (req, res) => {
  const userId = req.user.id;
  try {
    const [balance, thisMonth, lateTracker, todaySession] = await Promise.all([
      pool.query(`SELECT casual_leave, sick_leave, earned_leave FROM leave_balances WHERE user_id=$1`, [userId]),
      pool.query(`SELECT COUNT(*) FILTER (WHERE status='PRESENT') as present_days,
                         COUNT(*) as total_days,
                         AVG(total_work_minutes) as avg_minutes
                  FROM attendance_sessions
                  WHERE user_id=$1 AND DATE_TRUNC('month', login_time) = DATE_TRUNC('month', NOW())`, [userId]),
      pool.query(`SELECT late_count FROM late_login_tracker WHERE user_id=$1 AND month_year=TO_CHAR(NOW(),'YYYY-MM')`, [userId]),
      pool.query(`SELECT * FROM attendance_sessions WHERE user_id=$1 AND DATE(login_time)=CURRENT_DATE`, [userId])
    ]);
    res.json({
      leave_balance: balance.rows[0] || { casual_leave: 12, sick_leave: 12, earned_leave: 12 },
      attendance: thisMonth.rows[0],
      late_login_count: lateTracker.rows[0]?.late_count || 0,
      today_session: todaySession.rows[0] || null
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// GET /api/dashboard/team  (Team Lead — live AUX status)
app.get('/api/dashboard/team', auth(['TEAM_LEAD', 'ADMIN']), async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT u.full_name, u.employee_id,
              a.id as session_id, a.login_time, a.status,
              e.event_type as current_event,
              e.start_time as event_start
       FROM users u
       LEFT JOIN attendance_sessions a ON a.user_id = u.id AND DATE(a.login_time) = CURRENT_DATE
       LEFT JOIN LATERAL (
           SELECT event_type, start_time FROM attendance_events
           WHERE session_id = a.id AND end_time IS NULL
           ORDER BY start_time DESC LIMIT 1
       ) e ON TRUE
       WHERE u.team_id IN (SELECT id FROM teams WHERE team_lead=$1)
       AND u.status = 'ACTIVE'`, [req.user.id]
    );
    res.json(result.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// GET /api/dashboard/admin
app.get('/api/dashboard/admin', auth(['ADMIN', 'HR']), async (req, res) => {
  try {
    const [totals, lop, leaves] = await Promise.all([
      pool.query(`
        SELECT
          COUNT(DISTINCT u.id) as total_employees,
          COUNT(DISTINCT a.user_id) FILTER (WHERE DATE(a.login_time)=CURRENT_DATE) as present_today,
          COUNT(DISTINCT a.user_id) FILTER (WHERE DATE(a.login_time)=CURRENT_DATE AND a.late_login=TRUE) as late_today
        FROM users u LEFT JOIN attendance_sessions a ON a.user_id = u.id
        WHERE u.status = 'ACTIVE'`),
      pool.query(`SELECT COUNT(*) as total_lop, SUM(late_count) as total_late
                  FROM late_login_tracker WHERE month_year=TO_CHAR(NOW(),'YYYY-MM')`),
      pool.query(`SELECT COUNT(*) FILTER (WHERE approval_status='PENDING') as pending_leaves,
                         COUNT(*) FILTER (WHERE start_date=CURRENT_DATE AND approval_status='APPROVED') as on_leave_today
                  FROM leave_requests`)
    ]);
    res.json({ ...totals.rows[0], ...lop.rows[0], ...leaves.rows[0] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── START ───────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ AUX Backend running on port ${PORT}`));
