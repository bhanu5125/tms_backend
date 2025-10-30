const express = require("express");
const mysql = require("mysql2");
const db = require('./db');
const cors = require('cors');
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const app = express();
const PORT = 8000;
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ limit: "10mb", extended: true }));
const ExcelJS = require('exceljs');
const JWT_SECRET = "your-secret-key";
app.use(cors({
  origin: ['http://localhost:5174', 'http://localhost:5173', 'https://tcs.trafficcounting.com', 'https://dev.trafficcounting.in'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));


// List of tables
const tables = [
  "attendance", "bankdetails", "department", "nlog", "salary", "salary_bk",
  "salary_old", "salarytest", "salcals", "smsenc", "staff", "staffdates",
  "tblsource", "tblsourcebk", "testenc", "updatedattendancerecords",
  "updatedsalrecords", "user", "usergroup"
];

// Dynamic Route for All Tables
app.get("/get/:table", (req, res) => {
  const table = req.params.table;

  if (!tables.includes(table)) {
    return res.status(400).json({ error: "Invalid table name" });
  }

  const query = `SELECT * FROM ??`;
  db.query(query, [table], (err, results) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(results);
  });
});

// Get Staff Data with Department Mapping
app.get("/api/getstaff", (req, res) => {
  const query = `
    SELECT
      s.SId,
      s.Code,
      s.FirstName,
      s.LastName,
      s.Guardian,
      s.Address,
      s.PrimaryPhone,
      s.SecondaryPhone,
      CASE
          WHEN s.IsActive = BINARY 0x01 THEN 'InActive'
          ELSE 'Active'
      END AS IsActive,
      s.StaffType,
      s.DeptId,
      d.DeptName,
      s.CreatedDate,
      s.ModifiedDate,
      s.CreatedBy,
      s.ModifiedBy
    FROM staff s
    JOIN department d ON s.DeptId = d.ID;
  `;

  db.query(query, (err, results) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(results);
  });
});

const formatDateForMySQL = (date) => {
  if (!date) return null;

  // If already in YYYY-MM-DD format, return as-is
  if (typeof date === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(date)) {
    return date;
  }

  // If ISO string (e.g., "2020-01-06T00:00:00.000Z"), extract date part
  if (typeof date === 'string' && date.includes('T')) {
    return date.split('T')[0];
  }

  // Otherwise parse and format
  const d = new Date(date);
  const year = d.getFullYear();
  const month = String(d.getMonth() + 1).padStart(2, '0');
  const day = String(d.getDate()).padStart(2, '0');

  return `${year}-${month}-${day}`;
};

// API to handle form submission
app.post("/api/submit-form", (req, res) => {
  const { tblsourcebk, staff } = req.body;

  console.log("Received body:", req.body);

  // Validate required fields - you can add more robust validation as needed
  if (
    !staff.FirstName ||
    !staff.LastName ||
    !staff.PrimaryPhone ||
    !staff.DeptId ||
    !tblsourcebk.Bank_Acc_No
  ) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  // Prepare CALL statement with parameters
  const callProcedure = `
    CALL sp_AddStaff(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, @pSId);
    SELECT @pSId as StaffId;
  `;

  // Map input fields properly, using safe fallbacks where necessary
  const procedureParams = [
    staff.FirstName,
    staff.LastName,
    staff.Guardian || "",
    staff.Address || "",
    staff.PrimaryPhone,
    staff.SecondaryPhone || "",
    staff.StaffType === 0 ? null : staff.StaffType ,
    staff.DeptId,
    1, // CreatedBy, adjust accordingly
    1, // ModifiedBy, adjust accordingly
    tblsourcebk.Bank_Acc_No,
    tblsourcebk.Bank_Name || "",
    tblsourcebk.Branch || "", // Added Branch from tblsourcebk for completeness
    tblsourcebk.IFSC_Code || "",
    tblsourcebk.Aadhar_Number || "",
    tblsourcebk.DOJ ? new Date(tblsourcebk.DOJ) : null, // Date parsing safely
    tblsourcebk.Otherinfo || "", // Passing Otherinfo if provided
  ];
  console.log(procedureParams);

  db.query(callProcedure, procedureParams, (err, results) => {
    if (err) {
      console.error("Error calling stored procedure:", err);
      return res.status(500).json({ error: "Failed to execute stored procedure" });
    }

    // The results array: first element is result of CALL, second is SELECT @pSId
    const staffIdResult = results[1]; // Second result set contains SELECT @pSId
    const returnedStaffId = staffIdResult[0]?.StaffId;

    if (returnedStaffId === 10000) {
      return res.status(400).json({ error: "Staff already exists" });
    }

    return res.status(200).json({
      message: "Staff added successfully",
      staffId: returnedStaffId,
    });
  });
});

app.get("/api/get-staff/:code", (req, res) => {
  const { code } = req.params;

  const query = `CALL sp_GetStaffDetailsByCode(?);`;

  db.query(query, [code], (err, results) => {
    if (err) return res.status(500).json({ error: "Database error" });
    if (results[0].length === 0) return res.status(404).json({ error: "Not found" });

    const staffData = results[0][0];

    const responseData = {
      staff: {
        Code: staffData.Code,
        FirstName: staffData.FirstName,
        LastName: staffData.LastName,
        Guardian: staffData.Guardian,
        Address: staffData.Address,
        PrimaryPhone: staffData.PrimaryPhone,
        SecondaryPhone: staffData.SecondaryPhone,
        IsActive: staffData.IsActive,
        DeptId: staffData.DeptID,
        StaffType: staffData.StaffType,
        DOJ: staffData.DOJ ? formatDateForMySQL(staffData.DOJ) : null,
        DOR: staffData.DOR ? formatDateForMySQL(staffData.DOR) : null
      },
      tblsourcebk: {
        Aadhar_Number: staffData.Aadhar,
        Bank_Acc_No: staffData.AcctNo,
        Bank_Name: staffData.BankName,
        IFSC_Code: staffData.IFSC,
        Branch: staffData.Branch
      },
      resignationReason: staffData.ResignationReason
    };

    res.json(responseData);
  });
});

// Add date formatting helper
function formatDateForFrontend(date) {
  return new Date(date).toISOString().split('T')[0];
}

const generateReport = async (res, data, columns, filename) => {
  const workbook = new ExcelJS.Workbook();
  const worksheet = workbook.addWorksheet('SalReport');

  worksheet.columns = columns;
  data.forEach(row => worksheet.addRow(row));

  res.setHeader('Content-Type',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
  res.setHeader('Content-Disposition',
    `attachment; filename=${filename}-${Date.now()}.xlsx`);

  await workbook.xlsx.write(res);
  res.end();
};

app.get('/api/export-salary', (req, res) => {
  const { pKey, pDeptId, pYear, pMonth, pPEVal } = getParams(req);

  db.query("CALL sp_GenSalReport(?, ?, ?, ?, ?)",
    [pKey, pDeptId, pYear, pMonth, pPEVal],
    async (error, results) => {
      if (error) return handleError(res, error);

      const workbook = new ExcelJS.Workbook();
      const worksheet = workbook.addWorksheet('SalReport');

      // Set columns
      worksheet.columns = [
        { header: 'SNo', key: 'SNo' },
        { header: 'Code', key: 'Code' },
        { header: 'Name', key: 'Name' },
        { header: 'Salary', key: 'Salary' },
        { header: 'Absent', key: 'Absent' },
        { header: 'LOP', key: 'LOP' },
        { header: 'Gross Salary', key: 'GrossSal' },
        { header: 'Basic', key: 'Basic' },
        { header: 'HRA', key: 'HRA' },
        { header: 'Others', key: 'Others' },
        { header: 'PF', key: 'PF' },
        { header: 'ESI', key: 'ESI' },
        { header: 'Prof Tax', key: 'ProfTax' },
        { header: 'OT (In Days)', key: 'OT' },
        { header: 'OT Amount', key: 'OTAMOUNT' },
        { header: 'Bonus', key: 'Bonus' },
        { header: 'TDS', key: 'TDS' },
        { header: 'Net Salary', key: 'NetSal' }
      ];

      // Add data
      results[0].forEach(row => {
        worksheet.addRow({
          SNo: row.SNo,
          Code: row.Code,
          Name: row.Name,
          Salary: row.Salary,
          Absent: row.Absent,
          LOP: row.LOP,
          GrossSal: row.GrossSal,
          Basic: row.Basic,
          HRA: row.HRA,
          Others: row.Others,
          PF: row.PF,
          ESI: row.ESI,
          ProfTax: row.ProfTax,
          OT: row.OT,
          OTAMOUNT: row.OTAMOUNT,
          Bonus: row.Bonus,
          TDS: row.TDS,
          NetSal: row.NetSal
        });
      });

      // Set headers
      res.setHeader(
        'Content-Type',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
      );
      res.setHeader(
        'Content-Disposition',
        `attachment; filename=HTPLSalReport-${new Date().getTime()}.xlsx`
      );

      // Send the file
      await workbook.xlsx.write(res);
      res.end();
  });
});

app.get('/api/export-bank', (req, res) => {
  const { pKey, pDeptId, pYear, pMonth, pPEVal } = getParams(req);
  console.log("Bank");

  db.query("CALL sp_GenSalReport(?, ?, ?, ?, ?)",
    [pKey, pDeptId, pYear, pMonth, pPEVal],
    async (error, results) => {
      if (error) return handleError(res, error);

      const bankColumns = [
        { header: 'SNo', key: 'SNo' },
        { header: 'IFSC', key: 'IFSC' },
        { header: 'Account No', key: 'AcctNo' },
        { header: 'Name', key: 'Name' },
        { header: 'Net Salary', key: 'NetSal' },
      ];

      await generateReport(res, results[0], bankColumns, 'HTPLSalBankReport');
  });
});

// Helper functions
const getParams = (req) => ({
  pKey: req.query.pKey,
  pDeptId: parseInt(req.query.deptId) || 0,
  pYear: parseInt(req.query.year) || new Date().getFullYear(),
  pMonth: parseInt(req.query.month) || new Date().getMonth() + 1,
  pPEVal: parseInt(req.query.pPEVal) ?? 1,
});

const handleError = (res, error) => {
  console.error("Database error:", error);
  res.status(500).json({ error: "Failed to generate report" });
};

app.get("/api/get-salary", (req, res) => {
  const pKey = req.params.pKey;
  const did = 0;

  db.query("CALL sp_GetStaffSalary(?, ?)", [pKey, did], (error, results) => {
    if (error) {
      console.error("Error executing stored procedure:", error);
      return res.status(500).json({ error: "Database error" });
    }
    res.json(results[0]);
});
});

app.get('/api/get-payslip', async (req, res) => {
  try {
    const deptId = req.query.did || 0;
    const pYear = req.query.year || new Date().getFullYear();
    const pMonth = req.query.month || new Date().getMonth() + 1;

   db.query('CALL sp_GetStaffPaySlips(?, ?, ?)', [deptId, pYear, pMonth] , (error, results) => {
    if (error) {
      console.error("Error calling sp_GetStaffPaySlips:", error);
      return res.status(500).json({ error: "Database error" });
    }
    res.json(results[0]);
    });

  } catch (error) {
    console.error('Error fetching salary data:', error)
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.put("/api/update-salaries", (req, res) => {
  const { key, employees } = req.body;
  const expectedKey = key;

  if (!Array.isArray(employees) || employees.length === 0) {
    return res.status(400).json({ success: false, error: "No employee records provided" });
  }

  db.getConnection((err, connection) => {
    if (err) {
      console.error("Connection error:", err);
      return res.status(500).json({ success: false, error: "Failed to connect to database" });
    }

    connection.beginTransaction(err => {
      if (err) {
        connection.release();
        console.error("Transaction error:", err);
        return res.status(500).json({ success: false, error: "Transaction error" });
      }

      connection.query("TRUNCATE TABLE updatedsalrecords", (err) => {
        if (err) {
          return connection.rollback(() => {
            connection.release();
            console.error("TRUNCATE error:", err);
            res.status(500).json({ success: false, error: "Database error during TRUNCATE" });
          });
        }

        const values = employees.map(employee => [
          employee.SalId,
          employee.StaffId,
          employee.Salary,
          employee.Pf_ESIon || 0,
          employee.TDS || 0,
        ]);

        const insertQuery = `
          INSERT INTO updatedsalrecords
            (SalId, StaffId, Salary, Pf_ESIon, TDS)
          VALUES ?
        `;

        connection.query(insertQuery, [values], (err, insertResult) => {
          if (err) {
            return connection.rollback(() => {
              connection.release();
              console.error("INSERT error:", err);
              res.status(500).json({ success: false, error: "Database error during INSERT" });
            });
          }

          connection.query("CALL sp_UpdateStaffSalary(?)", [expectedKey], (err, procResults) => {
            if (err) {
              return connection.rollback(() => {
                connection.release();
                console.error("Procedure error:", err);
                res.status(500).json({ success: false, error: "Database error during procedure execution" });
              });
            }

            connection.commit(err => {
              if (err) {
                return connection.rollback(() => {
                  connection.release();
                  console.error("Commit error:", err);
                  res.status(500).json({ success: false, error: "Database error during commit" });
                });
              }

              connection.release();
              res.json({
                success: true,
                message: "Salaries updated successfully",
                affectedRows: insertResult.affectedRows,
                updatedData: procResults[0]
              });
            });
          });
        });
      });
    });
  });
});


app.get('/api/get-report', (req, res) => {
  const pKey = req.query.pKey;
  const pDeptId = parseInt(req.query.deptId) || 0;
  const pYear = parseInt(req.query.year) || new Date().getFullYear();
  const pMonth = parseInt(req.query.month) || (new Date().getMonth() + 1);
  const pPEVal = parseInt(req.query.pPEVal) ?? 1;
  console.log(pPEVal);

  const sql = "CALL sp_GenSalReport(?, ?, ?, ?, ?)";
  db.query(sql, [pKey, pDeptId, pYear, pMonth, pPEVal], (error, results) => {
      if (error) {
          console.error("Error executing stored procedure:", error);
          return res.status(500).json({ error: "Database error" });
      }
      //console.log(results[0][0])
      // Return the final SELECT result (usually the last result set)
      res.json(results[0]);
  });
});

app.get("/api/get-salary-calc", (req, res) => {
  const query = `
    SELECT * FROM salcals
  `;
  db.query(query, (err, results) => {
    if (err) return res.status(500).json({ error: "Database error" });
    res.json(results);
  });
});

const verifyToken = (req, res, next) => {
  const token = req.headers["authorization"]?.split(" ")[1];

  if (!token) {
    return res.status(403).json({ message: "No token provided" });
  }

  jwt.verify(token, "your-secret-key", (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    req.userId = decoded.userId;
    next();
  });
};


app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    const query = "SELECT * FROM user WHERE Username = ?";
    db.query(query, [username], async (err, results) => {
      if (err) {
        console.error("Database query error:", err);
        return res.status(500).json({ message: "Server error" });
      }

      if (results.length === 0) {
        return res.status(400).json({ message: "Invalid username or password" });
      }

      const user = results[0];

      const isMatch = await bcrypt.compare(password, user.Password);
      if (!isMatch) {
        return res.status(400).json({ message: "Invalid username or password" });
      }

      const token = jwt.sign({ userId: user.UserId }, "your-secret-key", {
        expiresIn: "1h",
      });

      const updateQuery = "UPDATE user SET LastLoginDate = NOW(6) WHERE UserId = ?";
      db.query(updateQuery, [user.UserId], (updateErr) => {
        if (updateErr) {
          console.error("Error updating LastLoginDate:", updateErr);
          // Don't block login, just log the error
        }
      });
      const userData = {
        userId: user.UserId,
        username: user.Username,
      };

      res.status(200).json({ authToken: token, user: userData });
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ message: "Server error" });
  }
});

// Get all users
app.get("/api/get-users", (req, res) => {
  const query = `
    SELECT UserId, Username FROM user
  `;
  db.query(query, (err, results) => {
    if (err) return res.status(500).json({ error: "Database error" , err});
    res.json(results);
  });
});

// Get user by ID
app.get("/api/get-user/:uid", (req, res) => {
  const { uid } = req.params;
  const query = `
    SELECT Username FROM user WHERE UserId = ?
  `;
  db.query(query, [uid], (err, results) => {
    if (err) return res.status(500).json({ error: "Database error" });
    res.json(results[0]);
  });
});

// Generate JWT for password change
app.post("/api/generate-token", (req, res) => {
  const { UserId } = req.body; // Use UserId instead of uid
  const token = jwt.sign({ userId: UserId }, "your-secret-key", { expiresIn: "1h" });
  res.json({ token });
});

app.get("/user/profile", verifyToken, async (req, res) => {
  try {
    const userId = req.userId; // Get the user ID from the request object

    // Fetch user data from the database
    const query = "SELECT * FROM user WHERE UserId = ?";
    db.query(query, [userId], (err, results) => {
      if (err) {
        console.error("Database query error:", err);
        return res.status(500).json({ message: "Server error" });
      }

      if (results.length === 0) {
        return res.status(404).json({ message: "User not found" });
      }

      const user = results[0];

      // Return user data (excluding sensitive information like password)
      const userData = {
        userId: user.UserId,
        username: user.Username,
      };

      res.status(200).json({ user: userData });
    });
  } catch (error) {
    console.error("Error fetching user profile:", error);
    res.status(500).json({ message: "Server error" });
  }
});

// Update password (protected by JWT)
app.post("/api/update-password", verifyToken, async (req, res) => {
  const userId = req.userId; // Get the user ID from the token
  const { password } = req.body;
  //console.log(userId)

  try {
    // Hash the new password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Update the password in the database
    const query = "UPDATE user SET Password = ? WHERE UserId = ?";
    db.query(query, [hashedPassword, userId], (err, results) => {
      if (err) {
        console.error("Database error:", err);
        return res.status(500).json({ error: "Database error" });
      }

      // Check if the password was updated
      if (results.affectedRows === 0) {
        return res.status(404).json({ error: "User not found" });
      }

      res.status(200).json({ success: true });
    });
  } catch (error) {
    console.error("Error updating password:", error);
    res.status(500).json({ error: "Server error" });
  }
});

app.put("/api/update-salary-calc/", (req, res) => {
  const { Basic, HRA, PF, ESI, TotalDays } = req.body;
  const query = `
    UPDATE salcals
    SET Basic = ?, HRA = ?, PF = ?, ESI = ?, TotalDays = ?
  `;
  db.query(query, [Basic, HRA, PF, ESI, TotalDays], (err, results) => {
    if (err) return res.status(500).json({ error: "Database error" });
    res.json({ message: "Payroll updated successfully" });
  });
});

app.put("/api/update-staff/:code", async (req, res) => {
  const { code } = req.params;
  const { tblsourcebk, staff, resignationReason } = req.body;

  try {
    // Get department name
    const [deptResult] = await db.promise().query(
      'SELECT DeptName FROM department WHERE ID = ?',
      [staff.DeptId]
    );

    // AUTO-SET IsActive based on termination date
    const isActive = staff.DOR ? 0 : (staff.IsActive ?? 1);

    const params = [
      code, // pCode
      staff.FirstName,
      staff.LastName,
      staff.Guardian,
      staff.Address,
      staff.PrimaryPhone,
      staff.SecondaryPhone,
      staff.StaffType || null,
      isActive, // Use computed isActive instead of staff.IsActive
      1, // ModifiedBy
      staff.DeptId,
      deptResult[0]?.DeptName || '', // pDeptName
      tblsourcebk.Bank_Acc_No,
      tblsourcebk.Bank_Name,
      tblsourcebk.Branch,
      tblsourcebk.IFSC_Code,
      tblsourcebk.Aadhar_Number,
      staff.DOJ ? formatDateForMySQL(staff.DOJ) : null,
      staff.DOR ? formatDateForMySQL(staff.DOR) : null,
      resignationReason || null,
      tblsourcebk.Otherinfo || null,
    ];

    const query = `CALL sp_UpdateStaffByCode(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, @pSuccess);
                   SELECT @pSuccess AS pSuccess;`;

    const [results] = await db.promise().query(query, params);
    const pSuccess = results[1][0].pSuccess;

    if (pSuccess === 1) {
      res.json({ message: "Staff updated successfully" });
    } else {
      const errorMap = {
        '-1': 'Invalid date sequence: Start date must be after previous termination',
        '-2': 'Termination date cannot be before start date'
      };
      res.status(400).json({
        error: errorMap[pSuccess] || 'Update failed'
      });
    }
  } catch (err) {
    console.error("Update error:", err);
    res.status(500).json({ error: "Database error" });
  }
});

// GET /api/attendance?date=YYYY-MM-DD&deptId=#
const MONTH_COLS = {
  1:  'Jan',  2: 'Feb',  3: 'Mar',  4: 'Apr',
  5:  'May',  6: 'Jun',  7: 'Jul',  8: 'Aug',
  9:  'Sep', 10: 'Oct', 11: 'Nov', 12: 'Dec'
};

// 3) GET /api/attendance?date=YYYY-MM-DD&deptId
app.get('/api/attendance', (req, res) => {
  const date = req.query.date;
  const deptId = req.query.deptId;

  if (!date) {
    return res.status(400).json({ error: 'date is required' });
  }

  const [yyyy, mm, dd] = date.split('-').map(Number);
  const year = yyyy;
  const month = mm;
  const day = dd;
  const dayColumn = `d${day}`;

  let sql = `
    SELECT
      s.SId AS SID,
      s.Code AS CODE,
      s.FirstName AS FIRSTNAME,
      s.LastName AS SURNAME,
      s.StaffType AS StaffType,
      d.DeptName AS DEPARTMENT,
      COALESCE(sma.${dayColumn} + 0, 0) AS is_present,
      sob.ot_days,
      sob.ot
    FROM staff s
    JOIN department d ON s.DeptId = d.ID
    LEFT JOIN staff_monthly_attendance sma
      ON s.SId = sma.staffid
      AND sma.year = ?
      AND sma.month = ?
    LEFT JOIN staff_ot_bonus sob
      ON s.SId = sob.staffid
      AND sob.year = ?
      AND sob.month = ?
    WHERE s.IsActive = 1
  `;

  const params = [year, month, year, month];
  if (deptId) {
    sql += ' AND s.DeptId = ?';
    params.push(deptId);
  }
  sql += ' ORDER BY s.DeptId, s.Code';

  db.query(sql, params, (err, rows) => {
    if (err) {
      console.error('GET /api/attendance error:', err);
      return res.status(500).json({ error: 'Server error' });
    }

    const result = rows.map((s) => {
      // Check if this specific day is an OT day
      const otDays = s.ot_days ? s.ot_days.split(',').map(Number) : [];
      const isOTDay = otDays.includes(day);

      return {
        SID: s.SID,
        CODE: s.CODE,
        FIRSTNAME: s.FIRSTNAME,
        SURNAME: s.SURNAME,
        StaffType: s.StaffType,
        DEPARTMENT: s.DEPARTMENT,
        attendance: s.is_present == 1 ? true : false,
        Year: year,
        isOT: isOTDay,
        otCount: s.ot || 0
      };
    });

    res.json(result);
  });
});

// POST /api/attendance
app.post('/api/attendance', (req, res) => {
  const records = req.body.records;
  if (!Array.isArray(records) || records.length === 0) {
    return res.status(400).json({ error: 'records must be a non-empty array' });
  }

  const theDate = records[0]?.date;
  if (!theDate) {
    return res.status(400).json({ error: 'Invalid date' });
  }

  const [yyyy, mm, dd] = theDate.split('-').map(Number);
  const year = yyyy;
  const month = mm;
  const day = dd;
  const dayColumn = `d${day}`;

  db.getConnection((connErr, connection) => {
    if (connErr) {
      console.error('Connection error:', connErr);
      return res.status(500).json({ error: 'Database connection failed' });
    }

    connection.beginTransaction((transErr) => {
      if (transErr) {
        console.error('Transaction begin error:', transErr);
        connection.release();
        return res.status(500).json({ error: 'Failed to begin transaction' });
      }

      const updateQueries = records.map((r) => {
        const staffId = r.staffId;
        const statusBit = r.status ? 1 : 0;
        const isOT = r.isOT === true; // frontend sends this

        return new Promise((resolve, reject) => {
          // STEP 1: ALWAYS save attendance first
          const attendanceSql = `
            INSERT INTO staff_monthly_attendance (staffid, year, month, ${dayColumn})
            VALUES (?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE ${dayColumn} = ?
          `;
          const attendanceValues = [staffId, year, month, statusBit, statusBit];

          connection.query(attendanceSql, attendanceValues, (err, result) => {
            if (err) {
              console.error('Insert/Update attendance error for staffId', staffId, ':', err);
              return reject(err);
            }

            // STEP 2: Handle OT logic based on checkbox state
            const selectSql = `
              SELECT ot, ot_days
              FROM staff_ot_bonus
              WHERE staffid = ? AND year = ? AND month = ?
            `;
            connection.query(selectSql, [staffId, year, month], (err, rows) => {
              if (err) {
                console.error('Select OT error:', err);
                return reject(err);
              }

              let ot = 0;
              let otDays = [];

              if (rows.length > 0) {
                ot = rows[0].ot || 0;
                otDays = rows[0].ot_days ? rows[0].ot_days.split(',').map(Number) : [];
              }

              // If OT checkbox is CHECKED
              if (isOT) {
                if (statusBit === 0) {
                  // Present: Add OT day if not already added
                  if (!otDays.includes(day)) {
                    otDays.push(day);
                    ot++;
                  }
                } else {
                  // Absent: Remove OT day if exists
                  if (otDays.includes(day)) {
                    otDays = otDays.filter(d => d !== day);
                    ot = Math.max(ot - 1, 0);
                  }
                }
              } else {
                // If OT checkbox is UNCHECKED - Remove this day from OT if it exists
                if (otDays.includes(day)) {
                  otDays = otDays.filter(d => d !== day);
                  ot = Math.max(ot - 1, 0);
                }
              }

              // If no OT days left and no record exists, just resolve
              if (rows.length === 0 && otDays.length === 0) {
                return resolve(result);
              }

              if (rows.length > 0) {
                // Update existing OT record
                const updateSql = `
                  UPDATE staff_ot_bonus
                  SET ot = ?, ot_days = ?
                  WHERE staffid = ? AND year = ? AND month = ?
                `;
                connection.query(updateSql, [ot, otDays.length ? otDays.join(',') : null, staffId, year, month], (err, result) => {
                  if (err) {
                    console.error('Update OT error:', err);
                    return reject(err);
                  }
                  resolve(result);
                });
              } else {
                // Insert new OT record (only if there are OT days to add)
                if (otDays.length > 0) {
                  const insertSql = `
                    INSERT INTO staff_ot_bonus (staffid, year, month, ot, ot_days)
                    VALUES (?, ?, ?, ?, ?)
                  `;
                  connection.query(insertSql, [staffId, year, month, ot, otDays.join(',')], (err, result) => {
                    if (err) {
                      console.error('Insert OT error:', err);
                      return reject(err);
                    }
                    resolve(result);
                  });
                } else {
                  resolve(result);
                }
              }
            });
          });
        });
      });

      Promise.all(updateQueries)
        .then(() => {
          connection.commit((commitErr) => {
            if (commitErr) {
              console.error('Commit error:', commitErr);
              return connection.rollback(() => {
                connection.release();
                res.status(500).json({ error: 'Transaction commit failed' });
              });
            }

            connection.release();
            res.json({ success: true, updated: records.length });
          });
        })
        .catch((queryErr) => {
          console.error('Query failed, rolling back:', queryErr);
          connection.rollback(() => {
            connection.release();
            res.status(500).json({ error: 'Failed to process attendance/OT records', details: queryErr.message });
          });
        });
    });
  });
});

// GET /api/ot-bonus
app.get('/api/ot-bonus', (req, res) => {
  let year = parseInt(req.query.year);
  let month = parseInt(req.query.month);
  let deptId = req.query.deptId;

  if (!year || !month) {
    const now = new Date();
    year = now.getFullYear();
    month = now.getMonth() + 1;
  }

  let sql = `
    SELECT
      s.SId AS SID,
      s.Code AS CODE,
      s.FirstName AS FIRSTNAME,
      s.LastName AS SURNAME,
      d.DeptName AS DEPARTMENT,
      COALESCE(sma.ot, 0) AS ot,
      COALESCE(sma.bonus, 0) AS bonus,
      sma.ot_days AS ot_days
    FROM staff s
    JOIN department d ON s.DeptId = d.ID
    LEFT JOIN staff_ot_bonus sma
      ON s.SId = sma.staffid
      AND sma.year = ?
      AND sma.month = ?
    WHERE s.IsActive = 1
  `;

  const params = [year, month];
  if (deptId) {
    sql += ' AND s.DeptId = ?';
    params.push(deptId);
  }

  sql += ' ORDER BY s.DeptId, s.Code';

  db.query(sql, params, (err, rows) => {
    if (err) {
      console.error('GET /api/ot-bonus error:', err);
      return res.status(500).json({ error: 'Server error' });
    }

    res.json(rows.map((s) => ({
      SID: s.SID,
      CODE: s.CODE,
      FIRSTNAME: s.FIRSTNAME,
      SURNAME: s.SURNAME,
      DEPARTMENT: s.DEPARTMENT,
      ot: s.ot,
      bonus: s.bonus,
      ot_days: s.ot_days
    })));
  });
});

// POST /api/ot-bonus
app.post('/api/ot-bonus', (req, res) => {
  const records = req.body.records;

  if (!Array.isArray(records) || records.length === 0) {
    return res.status(400).json({ error: 'records must be a non-empty array' });
  }

  const year = records[0]?.year;
  const month = records[0]?.month;

  db.getConnection((connErr, connection) => {
    if (connErr) {
      console.error('Connection error:', connErr);
      return res.status(500).json({ error: 'Database connection failed' });
    }

    connection.beginTransaction((transErr) => {
      if (transErr) {
        console.error('Transaction begin error:', transErr);
        connection.release();
        return res.status(500).json({ error: 'Failed to begin transaction' });
      }

      const updateQueries = records.map((r) => {
        const staffId = r.staffId;
        const bonus = r.bonus || 0;

        return new Promise((resolve, reject) => {
          // First check if record exists
          const checkSql = `
            SELECT staffid FROM staff_ot_bonus
            WHERE staffid = ? AND year = ? AND month = ?
          `;

          connection.query(checkSql, [staffId, year, month], (err, rows) => {
            if (err) {
              console.error('Check error for staffId', staffId, ':', err);
              return reject(err);
            }

            let sql, values;
            if (rows.length > 0) {
              // Record exists - only update bonus
              sql = `
                UPDATE staff_ot_bonus
                SET bonus = ?
                WHERE staffid = ? AND year = ? AND month = ?
              `;
              values = [bonus, staffId, year, month];
            } else {
              // Record doesn't exist - insert with ot=0
              sql = `
                INSERT INTO staff_ot_bonus (staffid, year, month, ot, bonus, ot_days)
                VALUES (?, ?, ?, 0, ?, NULL)
              `;
              values = [staffId, year, month, bonus];
            }

            connection.query(sql, values, (err, result) => {
              if (err) {
                console.error('Insert/Update error for staffId', staffId, ':', err);
                return reject(err);
              }
              resolve(result);
            });
          });
        });
      });

      Promise.all(updateQueries)
        .then(() => {
          connection.commit((commitErr) => {
            if (commitErr) {
              console.error('Commit error:', commitErr);
              return connection.rollback(() => {
                connection.release();
                res.status(500).json({ error: 'Transaction commit failed' });
              });
            }

            connection.release();
            res.json({ success: true, updated: records.length });
          });
        })
        .catch((queryErr) => {
          console.error('Query failed, rolling back:', queryErr);
          connection.rollback(() => {
            connection.release();
            res.status(500).json({ error: 'Failed to update bonus records', details: queryErr.message });
          });
        });
    });
  });
});

app.get('/api/get-deptname', (req, res) => {
  const query = `
    SELECT ID, DeptName FROM department
  `;
  db.query(query, (err, results) => {
    if (err) return res.status(500).json({ error: "Database error" });
    res.json(results);
  });
});

app.post('/api/verify-secret', (req, res) => {
  const { secretKey } = req.body;
  db.query("CALL sp_GetEnc(?)", [secretKey], (err, result) => {
    if (err)
      {
        console.log(err);
        return res.status(500).send(err);
      }
    res.json(result[0][0].SuperKey);
    //console.log(result[0][0].SuperKey);
});
});

// Start Server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});