const express = require("express")
const session = require("express-session")
const bcrypt = require("bcrypt")
const sqlite3 = require("sqlite3").verbose()
const path = require("path")
const multer = require("multer")
const fs = require("fs")

const app = express()
const PORT = process.env.PORT || 3000

// Database setup
const db = new sqlite3.Database("./database.db")

// Create uploads directory if it doesn't exist
const uploadsDir = path.join(__dirname, "public", "uploads", "profiles")
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true })
}

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadsDir)
  },
  filename: (req, file, cb) => {
    // Generate unique filename with timestamp
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9)
    cb(null, "profile-" + uniqueSuffix + path.extname(file.originalname))
  },
})

const fileFilter = (req, file, cb) => {
  // Check if file is an image
  if (file.mimetype.startsWith("image/")) {
    cb(null, true)
  } else {
    cb(new Error("Only image files are allowed!"), false)
  }
}

const upload = multer({
  storage: storage,
  fileFilter: fileFilter,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB limit
  },
})

// Middleware
app.use(express.urlencoded({ extended: true }))
app.use(express.json())
app.use(express.static("public"))
app.set("view engine", "ejs")
app.set("views", path.join(__dirname, "views"))

// Session configuration
app.use(
  session({
    secret: "your-secret-key-change-in-production",
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: false, // Set to true in production with HTTPS
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
    },
  }),
)

// Initialize database tables
function initializeDatabase() {
  // Users table - Updated to include profile_image
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    name TEXT NOT NULL,
    email TEXT,
    department TEXT,
    profile_image TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`)

  // Attendance table
  db.run(`CREATE TABLE IF NOT EXISTS attendance (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    date DATE NOT NULL,
    status TEXT NOT NULL DEFAULT 'present',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id),
    UNIQUE(user_id, date)
  )`)

  // Leave applications table
  db.run(`CREATE TABLE IF NOT EXISTS leave_applications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    start_date DATE NOT NULL,
    end_date DATE NOT NULL,
    reason TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    admin_comment TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
  )`)

  // Create default admin user
  const adminPassword = bcrypt.hashSync("admin123", 10)
  db.run(
    `INSERT OR IGNORE INTO users (username, password, role, name, email, department) 
          VALUES (?, ?, ?, ?, ?, ?)`,
    ["admin", adminPassword, "admin", "System Administrator", "admin@company.com", "IT"],
  )
}

// Authentication middleware
function requireAuth(req, res, next) {
  if (req.session.userId) {
    next()
  } else {
    res.redirect("/login")
  }
}

function requireAdmin(req, res, next) {
  if (req.session.userId && req.session.role === "admin") {
    next()
  } else {
    res.status(403).render("error", {
      message: "Access denied. Admin privileges required.",
      user: req.session.userId ? { role: req.session.role } : null,
    })
  }
}

// Routes
app.get("/", (req, res) => {
  if (req.session.userId) {
    if (req.session.role === "admin") {
      res.redirect("/admin/dashboard")
    } else {
      res.redirect("/user/dashboard")
    }
  } else {
    res.redirect("/login")
  }
})

app.get("/login", (req, res) => {
  if (req.session.userId) {
    res.redirect("/")
  } else {
    res.render("login", { error: null })
  }
})

app.post("/login", (req, res) => {
  const { username, password } = req.body

  db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
    if (err) {
      return res.render("login", { error: "Database error" })
    }

    if (!user || !bcrypt.compareSync(password, user.password)) {
      return res.render("login", { error: "Invalid username or password" })
    }

    req.session.userId = user.id
    req.session.username = user.username
    req.session.role = user.role
    req.session.name = user.name

    if (user.role === "admin") {
      res.redirect("/admin/dashboard")
    } else {
      res.redirect("/user/dashboard")
    }
  })
})

app.post("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("Session destruction error:", err)
    }
    res.redirect("/login")
  })
})

// Admin Routes
app.get("/admin/dashboard", requireAuth, requireAdmin, (req, res) => {
  // Get statistics
  db.all(
    `
    SELECT 
      (SELECT COUNT(*) FROM users WHERE role = 'user') as total_employees,
      (SELECT COUNT(*) FROM leave_applications WHERE status = 'pending') as pending_leaves,
      (SELECT COUNT(*) FROM attendance WHERE date = date('now')) as today_attendance
  `,
    (err, stats) => {
      if (err) {
        console.error(err)
        return res.render("error", { message: "Database error", user: req.session })
      }

      res.render("admin/dashboard", {
        user: req.session,
        stats: stats[0] || { total_employees: 0, pending_leaves: 0, today_attendance: 0 },
      })
    },
  )
})

app.get("/admin/employees", requireAuth, requireAdmin, (req, res) => {
  db.all(
    'SELECT id, username, name, email, department, profile_image, created_at FROM users WHERE role = "user"',
    (err, employees) => {
      if (err) {
        console.error(err)
        return res.render("error", { message: "Database error", user: req.session })
      }

      res.render("admin/employees", { user: req.session, employees })
    },
  )
})

app.get("/admin/add-employee", requireAuth, requireAdmin, (req, res) => {
  res.render("admin/add-employee", { user: req.session, error: null })
})

app.post("/admin/add-employee", requireAuth, requireAdmin, upload.single("profileImage"), (req, res) => {
  const { username, password, name, email, department } = req.body

  if (!username || !password || !name) {
    // Delete uploaded file if validation fails
    if (req.file) {
      fs.unlink(req.file.path, (err) => {
        if (err) console.error("Error deleting file:", err)
      })
    }
    return res.render("admin/add-employee", {
      user: req.session,
      error: "Username, password, and name are required",
    })
  }

  const hashedPassword = bcrypt.hashSync(password, 10)
  const profileImage = req.file ? req.file.filename : null

  db.run(
    "INSERT INTO users (username, password, name, email, department, profile_image, role) VALUES (?, ?, ?, ?, ?, ?, ?)",
    [username, hashedPassword, name, email, department, profileImage, "user"],
    (err) => {
      if (err) {
        // Delete uploaded file if database insertion fails
        if (req.file) {
          fs.unlink(req.file.path, (err) => {
            if (err) console.error("Error deleting file:", err)
          })
        }

        if (err.code === "SQLITE_CONSTRAINT") {
          return res.render("admin/add-employee", {
            user: req.session,
            error: "Username already exists",
          })
        }
        console.error(err)
        return res.render("admin/add-employee", {
          user: req.session,
          error: "Database error",
        })
      }

      res.redirect("/admin/employees")
    },
  )
})

app.get("/admin/leave-applications", requireAuth, requireAdmin, (req, res) => {
  db.all(
    `
    SELECT la.*, u.name as employee_name 
    FROM leave_applications la 
    JOIN users u ON la.user_id = u.id 
    ORDER BY la.created_at DESC
  `,
    (err, applications) => {
      if (err) {
        console.error(err)
        return res.render("error", { message: "Database error", user: req.session })
      }

      res.render("admin/leave-applications", { user: req.session, applications })
    },
  )
})

app.post("/admin/leave-action", requireAuth, requireAdmin, (req, res) => {
  const { applicationId, action, comment } = req.body

  db.run(
    "UPDATE leave_applications SET status = ?, admin_comment = ? WHERE id = ?",
    [action, comment || null, applicationId],
    (err) => {
      if (err) {
        console.error(err)
      }
      res.redirect("/admin/leave-applications")
    },
  )
})

// Edit Employee Route
app.get("/admin/edit-employee/:id", requireAuth, requireAdmin, (req, res) => {
  const employeeId = req.params.id

  db.get(
    'SELECT id, username, name, email, department, profile_image FROM users WHERE id = ? AND role = "user"',
    [employeeId],
    (err, employee) => {
      if (err) {
        console.error(err)
        return res.render("error", { message: "Database error", user: req.session })
      }

      if (!employee) {
        return res.render("error", { message: "Employee not found", user: req.session })
      }

      res.render("admin/edit-employee", { user: req.session, employee, error: null })
    },
  )
})

// Update Employee Route
app.post("/admin/edit-employee/:id", requireAuth, requireAdmin, upload.single("profileImage"), (req, res) => {
  const employeeId = req.params.id
  const { username, name, email, department, password, removeImage } = req.body

  if (!username || !name) {
    // Delete uploaded file if validation fails
    if (req.file) {
      fs.unlink(req.file.path, (err) => {
        if (err) console.error("Error deleting file:", err)
      })
    }
    return db.get(
      'SELECT id, username, name, email, department, profile_image FROM users WHERE id = ? AND role = "user"',
      [employeeId],
      (err, employee) => {
        if (err || !employee) {
          return res.render("error", { message: "Employee not found", user: req.session })
        }
        res.render("admin/edit-employee", {
          user: req.session,
          employee,
          error: "Username and name are required",
        })
      },
    )
  }

  // Get current employee data to handle image updates
  db.get('SELECT profile_image FROM users WHERE id = ? AND role = "user"', [employeeId], (err, currentEmployee) => {
    if (err || !currentEmployee) {
      if (req.file) {
        fs.unlink(req.file.path, (err) => {
          if (err) console.error("Error deleting file:", err)
        })
      }
      return res.render("error", { message: "Employee not found", user: req.session })
    }

    // Build update query
    let updateQuery = "UPDATE users SET username = ?, name = ?, email = ?, department = ?"
    const updateParams = [username, name, email, department]

    // Handle profile image update
    let newProfileImage = currentEmployee.profile_image

    if (removeImage === "true") {
      // Remove existing image
      if (currentEmployee.profile_image) {
        const imagePath = path.join(uploadsDir, currentEmployee.profile_image)
        fs.unlink(imagePath, (err) => {
          if (err) console.error("Error deleting old image:", err)
        })
      }
      newProfileImage = null
    } else if (req.file) {
      // New image uploaded
      if (currentEmployee.profile_image) {
        const oldImagePath = path.join(uploadsDir, currentEmployee.profile_image)
        fs.unlink(oldImagePath, (err) => {
          if (err) console.error("Error deleting old image:", err)
        })
      }
      newProfileImage = req.file.filename
    }

    updateQuery += ", profile_image = ?"
    updateParams.push(newProfileImage)

    // Handle password update
    if (password && password.trim() !== "") {
      const hashedPassword = bcrypt.hashSync(password, 10)
      updateQuery += ", password = ?"
      updateParams.push(hashedPassword)
    }

    updateQuery += " WHERE id = ? AND role = 'user'"
    updateParams.push(employeeId)

    db.run(updateQuery, updateParams, function (err) {
      if (err) {
        console.error(err)
        // Delete uploaded file if database update fails
        if (req.file) {
          fs.unlink(req.file.path, (err) => {
            if (err) console.error("Error deleting file:", err)
          })
        }

        if (err.code === "SQLITE_CONSTRAINT") {
          return db.get(
            'SELECT id, username, name, email, department, profile_image FROM users WHERE id = ? AND role = "user"',
            [employeeId],
            (err, employee) => {
              if (err || !employee) {
                return res.render("error", { message: "Employee not found", user: req.session })
              }
              res.render("admin/edit-employee", {
                user: req.session,
                employee,
                error: "Username already exists",
              })
            },
          )
        }
        return db.get(
          'SELECT id, username, name, email, department, profile_image FROM users WHERE id = ? AND role = "user"',
          [employeeId],
          (err, employee) => {
            if (err || !employee) {
              return res.render("error", { message: "Employee not found", user: req.session })
            }
            res.render("admin/edit-employee", {
              user: req.session,
              employee,
              error: "Database error occurred",
            })
          },
        )
      }

      if (this.changes === 0) {
        return res.render("error", { message: "Employee not found", user: req.session })
      }

      res.redirect("/admin/employees")
    })
  })
})

// Delete Employee Route
app.post("/admin/delete-employee/:id", requireAuth, requireAdmin, (req, res) => {
  const employeeId = req.params.id

  // Get employee data to delete profile image
  db.get('SELECT profile_image FROM users WHERE id = ? AND role = "user"', [employeeId], (err, employee) => {
    if (err) {
      console.error("Error fetching employee:", err)
      return res.render("error", { message: "Database error", user: req.session })
    }

    // Start a transaction to delete employee and related data
    db.serialize(() => {
      // Delete related attendance records
      db.run("DELETE FROM attendance WHERE user_id = ?", [employeeId], (err) => {
        if (err) {
          console.error("Error deleting attendance records:", err)
        }
      })

      // Delete related leave applications
      db.run("DELETE FROM leave_applications WHERE user_id = ?", [employeeId], (err) => {
        if (err) {
          console.error("Error deleting leave applications:", err)
        }
      })

      // Delete the employee
      db.run('DELETE FROM users WHERE id = ? AND role = "user"', [employeeId], function (err) {
        if (err) {
          console.error("Error deleting employee:", err)
          return res.render("error", { message: "Database error", user: req.session })
        }

        if (this.changes === 0) {
          return res.render("error", { message: "Employee not found", user: req.session })
        }

        // Delete profile image if exists
        if (employee && employee.profile_image) {
          const imagePath = path.join(uploadsDir, employee.profile_image)
          fs.unlink(imagePath, (err) => {
            if (err) console.error("Error deleting profile image:", err)
          })
        }

        res.redirect("/admin/employees")
      })
    })
  })
})

// View Employee Details Route
app.get("/admin/view-employee/:id", requireAuth, requireAdmin, (req, res) => {
  const employeeId = req.params.id

  // Get employee details
  db.get(
    'SELECT id, username, name, email, department, profile_image, created_at FROM users WHERE id = ? AND role = "user"',
    [employeeId],
    (err, employee) => {
      if (err) {
        console.error(err)
        return res.render("error", { message: "Database error", user: req.session })
      }

      if (!employee) {
        return res.render("error", { message: "Employee not found", user: req.session })
      }

      // Get employee's attendance summary
      db.all(
        `SELECT 
          COUNT(*) as total_days,
          SUM(CASE WHEN status = 'present' THEN 1 ELSE 0 END) as present_days,
          SUM(CASE WHEN status = 'absent' THEN 1 ELSE 0 END) as absent_days
        FROM attendance WHERE user_id = ?`,
        [employeeId],
        (err, attendanceSummary) => {
          if (err) {
            console.error(err)
            return res.render("error", { message: "Database error", user: req.session })
          }

          // Get recent attendance records
          db.all(
            "SELECT * FROM attendance WHERE user_id = ? ORDER BY date DESC LIMIT 10",
            [employeeId],
            (err, recentAttendance) => {
              if (err) {
                console.error(err)
                return res.render("error", { message: "Database error", user: req.session })
              }

              // Get leave applications
              db.all(
                "SELECT * FROM leave_applications WHERE user_id = ? ORDER BY created_at DESC",
                [employeeId],
                (err, leaveApplications) => {
                  if (err) {
                    console.error(err)
                    return res.render("error", { message: "Database error", user: req.session })
                  }

                  res.render("admin/view-employee", {
                    user: req.session,
                    employee,
                    attendanceSummary: attendanceSummary[0] || {
                      total_days: 0,
                      present_days: 0,
                      absent_days: 0,
                    },
                    recentAttendance,
                    leaveApplications,
                  })
                },
              )
            },
          )
        },
      )
    },
  )
})

// Bulk Operations Route
app.get("/admin/bulk-operations", requireAuth, requireAdmin, (req, res) => {
  db.all('SELECT id, username, name, email, department FROM users WHERE role = "user"', (err, employees) => {
    if (err) {
      console.error(err)
      return res.render("error", { message: "Database error", user: req.session })
    }

    res.render("admin/bulk-operations", { user: req.session, employees, message: null })
  })
})

// Bulk Delete Route
app.post("/admin/bulk-delete", requireAuth, requireAdmin, (req, res) => {
  const { selectedEmployees } = req.body

  if (!selectedEmployees || selectedEmployees.length === 0) {
    return db.all('SELECT id, username, name, email, department FROM users WHERE role = "user"', (err, employees) => {
      if (err) {
        console.error(err)
        return res.render("error", { message: "Database error", user: req.session })
      }
      res.render("admin/bulk-operations", {
        user: req.session,
        employees,
        message: "Please select at least one employee to delete",
      })
    })
  }

  const employeeIds = Array.isArray(selectedEmployees) ? selectedEmployees : [selectedEmployees]
  const placeholders = employeeIds.map(() => "?").join(",")

  // Get profile images to delete
  db.all(
    `SELECT profile_image FROM users WHERE id IN (${placeholders}) AND role = 'user'`,
    employeeIds,
    (err, employees) => {
      if (err) {
        console.error(err)
        return res.render("error", { message: "Database error", user: req.session })
      }

      db.serialize(() => {
        // Delete related records first
        db.run(`DELETE FROM attendance WHERE user_id IN (${placeholders})`, employeeIds)
        db.run(`DELETE FROM leave_applications WHERE user_id IN (${placeholders})`, employeeIds)

        // Delete employees
        db.run(`DELETE FROM users WHERE id IN (${placeholders}) AND role = 'user'`, employeeIds, (err) => {
          if (err) {
            console.error("Error in bulk delete:", err)
            return res.render("error", { message: "Database error", user: req.session })
          }

          // Delete profile images
          employees.forEach((employee) => {
            if (employee.profile_image) {
              const imagePath = path.join(uploadsDir, employee.profile_image)
              fs.unlink(imagePath, (err) => {
                if (err) console.error("Error deleting profile image:", err)
              })
            }
          })

          res.redirect("/admin/employees")
        })
      })
    },
  )
})

// User Routes
app.get("/user/dashboard", requireAuth, (req, res) => {
  if (req.session.role === "admin") {
    return res.redirect("/admin/dashboard")
  }

  // Get user's recent attendance and leave applications
  db.all(
    `
    SELECT * FROM attendance 
    WHERE user_id = ? 
    ORDER BY date DESC 
    LIMIT 5
  `,
    [req.session.userId],
    (err, attendance) => {
      if (err) {
        console.error(err)
        return res.render("error", { message: "Database error", user: req.session })
      }

      db.all(
        `
      SELECT * FROM leave_applications 
      WHERE user_id = ? 
      ORDER BY created_at DESC 
      LIMIT 5
    `,
        [req.session.userId],
        (err, leaves) => {
          if (err) {
            console.error(err)
            return res.render("error", { message: "Database error", user: req.session })
          }

          res.render("user/dashboard", {
            user: req.session,
            attendance,
            leaves,
          })
        },
      )
    },
  )
})

app.get("/user/attendance", requireAuth, (req, res) => {
  if (req.session.role === "admin") {
    return res.redirect("/admin/dashboard")
  }

  // Check if user already marked attendance today
  const today = new Date().toISOString().split("T")[0]

  db.get(
    "SELECT * FROM attendance WHERE user_id = ? AND date = ?",
    [req.session.userId, today],
    (err, todayAttendance) => {
      if (err) {
        console.error(err)
        return res.render("error", { message: "Database error", user: req.session })
      }

      // Get recent attendance records
      db.all(
        "SELECT * FROM attendance WHERE user_id = ? ORDER BY date DESC LIMIT 10",
        [req.session.userId],
        (err, attendance) => {
          if (err) {
            console.error(err)
            return res.render("error", { message: "Database error", user: req.session })
          }

          res.render("user/attendance", {
            user: req.session,
            attendance,
            todayAttendance,
            today,
          })
        },
      )
    },
  )
})

app.post("/user/mark-attendance", requireAuth, (req, res) => {
  if (req.session.role === "admin") {
    return res.redirect("/admin/dashboard")
  }

  const today = new Date().toISOString().split("T")[0]

  db.run(
    "INSERT OR REPLACE INTO attendance (user_id, date, status) VALUES (?, ?, ?)",
    [req.session.userId, today, "present"],
    (err) => {
      if (err) {
        console.error(err)
      }
      res.redirect("/user/attendance")
    },
  )
})

app.get("/user/leave", requireAuth, (req, res) => {
  if (req.session.role === "admin") {
    return res.redirect("/admin/dashboard")
  }

  db.all(
    "SELECT * FROM leave_applications WHERE user_id = ? ORDER BY created_at DESC",
    [req.session.userId],
    (err, applications) => {
      if (err) {
        console.error(err)
        return res.render("error", { message: "Database error", user: req.session })
      }

      res.render("user/leave", { user: req.session, applications })
    },
  )
})

app.post("/user/apply-leave", requireAuth, (req, res) => {
  if (req.session.role === "admin") {
    return res.redirect("/admin/dashboard")
  }

  const { startDate, endDate, reason } = req.body

  if (!startDate || !endDate || !reason) {
    return res.redirect("/user/leave")
  }

  db.run(
    "INSERT INTO leave_applications (user_id, start_date, end_date, reason) VALUES (?, ?, ?, ?)",
    [req.session.userId, startDate, endDate, reason],
    (err) => {
      if (err) {
        console.error(err)
      }
      res.redirect("/user/leave")
    },
  )
})

// User Profile Routes
app.get("/user/profile", requireAuth, (req, res) => {
  if (req.session.role === "admin") {
    return res.redirect("/admin/dashboard")
  }

  // Get user's complete profile information
  db.get(
    "SELECT id, username, name, email, department, profile_image, created_at FROM users WHERE id = ?",
    [req.session.userId],
    (err, userProfile) => {
      if (err) {
        console.error(err)
        return res.render("error", { message: "Database error", user: req.session })
      }

      if (!userProfile) {
        return res.render("error", { message: "User profile not found", user: req.session })
      }

      // Get user's attendance summary
      db.all(
        `SELECT 
          COUNT(*) as total_days,
          SUM(CASE WHEN status = 'present' THEN 1 ELSE 0 END) as present_days,
          SUM(CASE WHEN status = 'absent' THEN 1 ELSE 0 END) as absent_days
        FROM attendance WHERE user_id = ?`,
        [req.session.userId],
        (err, attendanceSummary) => {
          if (err) {
            console.error(err)
            return res.render("error", { message: "Database error", user: req.session })
          }

          // Get leave applications summary
          db.all(
            `SELECT 
              COUNT(*) as total_applications,
              SUM(CASE WHEN status = 'approved' THEN 1 ELSE 0 END) as approved_leaves,
              SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending_leaves,
              SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END) as rejected_leaves
            FROM leave_applications WHERE user_id = ?`,
            [req.session.userId],
            (err, leaveSummary) => {
              if (err) {
                console.error(err)
                return res.render("error", { message: "Database error", user: req.session })
              }

              res.render("user/profile", {
                user: req.session,
                userProfile,
                attendanceSummary: attendanceSummary[0] || {
                  total_days: 0,
                  present_days: 0,
                  absent_days: 0,
                },
                leaveSummary: leaveSummary[0] || {
                  total_applications: 0,
                  approved_leaves: 0,
                  pending_leaves: 0,
                  rejected_leaves: 0,
                },
                error: null,
                success: null,
              })
            },
          )
        },
      )
    },
  )
})

// Update User Profile Route
app.post("/user/update-profile", requireAuth, upload.single("profileImage"), (req, res) => {
  if (req.session.role === "admin") {
    return res.redirect("/admin/dashboard")
  }

  const { name, email, currentPassword, newPassword, confirmPassword, removeImage } = req.body

  if (!name) {
    if (req.file) {
      fs.unlink(req.file.path, (err) => {
        if (err) console.error("Error deleting file:", err)
      })
    }
    return res.redirect("/user/profile?error=Name is required")
  }

  // Get current user data for validation
  db.get("SELECT * FROM users WHERE id = ?", [req.session.userId], (err, currentUser) => {
    if (err) {
      console.error(err)
      if (req.file) {
        fs.unlink(req.file.path, (err) => {
          if (err) console.error("Error deleting file:", err)
        })
      }
      return res.redirect("/user/profile?error=Database error")
    }

    if (!currentUser) {
      if (req.file) {
        fs.unlink(req.file.path, (err) => {
          if (err) console.error("Error deleting file:", err)
        })
      }
      return res.redirect("/user/profile?error=User not found")
    }

    // Handle profile image update
    let newProfileImage = currentUser.profile_image

    if (removeImage === "true") {
      // Remove existing image
      if (currentUser.profile_image) {
        const imagePath = path.join(uploadsDir, currentUser.profile_image)
        fs.unlink(imagePath, (err) => {
          if (err) console.error("Error deleting old image:", err)
        })
      }
      newProfileImage = null
    } else if (req.file) {
      // New image uploaded
      if (currentUser.profile_image) {
        const oldImagePath = path.join(uploadsDir, currentUser.profile_image)
        fs.unlink(oldImagePath, (err) => {
          if (err) console.error("Error deleting old image:", err)
        })
      }
      newProfileImage = req.file.filename
    }

    // Check if password change is requested
    if (newPassword && newPassword.trim() !== "") {
      // Validate current password
      if (!currentPassword || !bcrypt.compareSync(currentPassword, currentUser.password)) {
        if (req.file) {
          fs.unlink(req.file.path, (err) => {
            if (err) console.error("Error deleting file:", err)
          })
        }
        return res.redirect("/user/profile?error=Current password is incorrect")
      }

      // Validate new password confirmation
      if (newPassword !== confirmPassword) {
        if (req.file) {
          fs.unlink(req.file.path, (err) => {
            if (err) console.error("Error deleting file:", err)
          })
        }
        return res.redirect("/user/profile?error=New passwords do not match")
      }

      // Validate new password strength
      if (newPassword.length < 6) {
        if (req.file) {
          fs.unlink(req.file.path, (err) => {
            if (err) console.error("Error deleting file:", err)
          })
        }
        return res.redirect("/user/profile?error=New password must be at least 6 characters long")
      }

      // Update with new password
      const hashedPassword = bcrypt.hashSync(newPassword, 10)
      db.run(
        "UPDATE users SET name = ?, email = ?, password = ?, profile_image = ? WHERE id = ?",
        [name, email, hashedPassword, newProfileImage, req.session.userId],
        (err) => {
          if (err) {
            console.error(err)
            if (req.file) {
              fs.unlink(req.file.path, (err) => {
                if (err) console.error("Error deleting file:", err)
              })
            }
            return res.redirect("/user/profile?error=Database error occurred")
          }

          // Update session name
          req.session.name = name
          res.redirect("/user/profile?success=Profile and password updated successfully")
        },
      )
    } else {
      // Update without password change
      db.run(
        "UPDATE users SET name = ?, email = ?, profile_image = ? WHERE id = ?",
        [name, email, newProfileImage, req.session.userId],
        (err) => {
          if (err) {
            console.error(err)
            if (req.file) {
              fs.unlink(req.file.path, (err) => {
                if (err) console.error("Error deleting file:", err)
              })
            }
            return res.redirect("/user/profile?error=Database error occurred")
          }

          // Update session name
          req.session.name = name
          res.redirect("/user/profile?success=Profile updated successfully")
        },
      )
    }
  })
})

// Initialize database and start server
initializeDatabase()

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`)
  console.log("Default admin credentials: username: admin, password: admin123")
})
