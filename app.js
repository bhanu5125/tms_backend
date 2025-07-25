const express = require("express");
const mysql = require("mysql2");
const db = require('./db');
const cors = require('cors');
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const app = express();
const PORT = 5000;
app.use(express.json());
const ExcelJS = require('exceljs');
const JWT_SECRET = "your-secret-key"; 
app.use(cors({
  origin: ['https://starter-eight-brown.vercel.app', 'http://localhost:5174', 'https://trafficcounting.in'],
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
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
  const istOffset = 5.5 * 60 * 60 * 1000; // IST is UTC +5:30
  const istDate = new Date(new Date(date).getTime() + istOffset);
  
  const day = String(istDate.getDate()).padStart(2, "0");
  const month = String(istDate.getMonth() + 1).padStart(2, "0"); // Months are 0-based
  const year = istDate.getFullYear();

  return `${day}-${month}-${year}`;
};
function formatDate2ForMySQL(date) {
  if (!date) return null;

  // If the input is already a Date object, use it directly
  const jsDate = date instanceof Date ? date : new Date(date);

  // Extract year, month, day, hours, minutes, and seconds
  const year = jsDate.getFullYear();
  const month = String(jsDate.getMonth() + 1).padStart(2, "0"); // Months are 0-based
  const day = String(jsDate.getDate()).padStart(2, "0");
  const hours = String(jsDate.getHours()).padStart(2, "0");
  const minutes = String(jsDate.getMinutes()).padStart(2, "0");
  const seconds = String(jsDate.getSeconds()).padStart(2, "0");

  // Format as YYYY-MM-DD HH:MM:SS
  return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;
}

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
    staff.StaffType === 0 ? null : staff.StaffType,
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
  pKey: "Hr!$h!kesh",
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
  const pKey = "Hr!$h!kesh";
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
  const expectedKey = "Hr!$h!kesh";
  const { key, employees } = req.body;
  //console.log(req.body.employees[0])
  
  // Validate the request
  if (key !== expectedKey) {
    return res.status(401).json({ success: false, error: "Invalid authentication key" });
  }

  if (!Array.isArray(employees) || employees.length === 0) {
    return res.status(400).json({ success: false, error: "No employee records provided" });
  }

  // Begin transaction
  db.beginTransaction(err => {
    if (err) {
      console.error("Transaction error:", err);
      return res.status(500).json({ success: false, error: "Transaction error" });
    }

    // Clear previous updates
    db.query("TRUNCATE TABLE updatedsalrecords", (err) => {
      if (err) {
        return db.rollback(() => {
          console.error("TRUNCATE error:", err);
          res.status(500).json({ success: false, error: "Database error during TRUNCATE" });
        });
      }

      // Prepare the values for bulk insert
      const values = employees.map(employee => [
        employee.SalId,
        employee.StaffId,
        employee.Salary,
        employee.Pf_ESIon || 0,
        employee.TDS || 0,
      ]);

      // Insert new updates
      const insertQuery = `
        INSERT INTO updatedsalrecords 
          (SalId, StaffId, Salary, Pf_ESIon, TDS) 
        VALUES ?`;
      
      db.query(insertQuery, [values], (err, insertResult) => {
        if (err) {
          return db.rollback(() => {
            console.error("INSERT error:", err);
            res.status(500).json({ success: false, error: "Database error during INSERT" });
          });
        }

        // Execute stored procedure
        db.query("CALL sp_UpdateStaffSalary(?)", [expectedKey], (err, procResults) => {
          if (err) {
            return db.rollback(() => {
              console.error("Procedure error:", err);
              res.status(500).json({ success: false, error: "Database error during procedure execution" });
            });
          }

          // Commit transaction
          db.commit(err => {
            if (err) {
              return db.rollback(() => {
                console.error("Commit error:", err);
                res.status(500).json({ success: false, error: "Database error during commit" });
              });
            }

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

app.get('/api/get-report', (req, res) => {
  const pKey = "Hr!$h!kesh";
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

    const params = [
      code, // pCode
      staff.FirstName,
      staff.LastName,
      staff.Guardian,
      staff.Address,
      staff.PrimaryPhone,
      staff.SecondaryPhone,
      staff.StaffType || null,
      staff.IsActive,
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

// 3) GET /api/attendance?date=YYYY-MM-DD&deptId=…
app.get('/api/attendance', (req, res) => {
  const date = req.query.date;
  const deptId = req.query.deptId;

  if (!date) {
    return res.status(400).json({ error: 'date is required' });
  }

  const year = new Date(date).getFullYear();
  const month = new Date(date).getMonth() + 1; // Months are 0-based
  const day = new Date(date).getDate();

  // Dynamically get the correct daily column like d1, d15, etc.
  const dayColumn = `d${day}`;

  let sql = `
    SELECT
      s.SId AS SID,
      s.Code AS CODE,
      s.FirstName AS FIRSTNAME,
      s.LastName AS SURNAME,
      d.DeptName AS DEPARTMENT,
      COALESCE(sma.${dayColumn} + 0, 0) AS is_present,
      COALESCE(sma.ot, 0) AS ot,
      COALESCE(sma.bonus, 0) AS bonus
    FROM staff s
    JOIN department d ON s.DeptId = d.ID
    LEFT JOIN staff_monthly_attendance sma 
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
      console.error('GET /api/attendance error:', err);
      return res.status(500).json({ error: 'Server error' });
    }

    const result = rows.map((s) => ({
      SID: s.SID,
      CODE: s.CODE,
      FIRSTNAME: s.FIRSTNAME,
      SURNAME: s.SURNAME,
      DEPARTMENT: s.DEPARTMENT,
      attendance: s.is_present == 1 ? true : false, // true means absent
      ot: s.ot,
      bonus: s.bonus,
      Year: year
    }));

    res.json(result);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/attendance - Save attendance records
// Body: { records:[ { staffId, date:'YYYY-MM-DD', status:'present'|'absent' }, … ] }
app.post('/api/attendance', (req, res) => {
  const records = req.body.records;
  if (!Array.isArray(records) || records.length === 0) {
    return res.status(400).json({ error: 'records must be a non-empty array' });
  }

  const theDate = records[0]?.date;
  if (!theDate) return res.status(400).json({ error: 'Invalid date' });

  const year = new Date(theDate).getFullYear();
  const month = new Date(theDate).getMonth() + 1;
  const day = new Date(theDate).getDate();
  const dayColumn = `d${day}`;

  db.beginTransaction((err) => {
    if (err) {
      console.error('Transaction begin error:', err);
      return res.status(500).json({ error: 'Failed to begin transaction' });
    }

    const queries = records.map((r) => {
      const statusBit = r.status ? 1 : 0;
      const staffId = r.staffId;
      const ot = r.ot || 0;
      const bonus = r.bonus || 0;

      return new Promise((resolve, reject) => {
        const sql = `
          INSERT INTO staff_monthly_attendance (staffid, year, month, ${dayColumn}, ot, bonus)
          VALUES (?, ?, ?, ?, ?, ?)
          ON DUPLICATE KEY UPDATE
            ${dayColumn} = ?,
            ot = VALUES(ot),
            bonus = VALUES(bonus)
        `;

        db.query(sql, [staffId, year, month, statusBit, ot, bonus, statusBit], (err, result) => {
          if (err) {
            console.error('Insert/Update error:', err);
            return reject(err);
          }
          resolve(result);
        });
      });
    });

    Promise.all(queries)
      .then((results) => {
        db.commit((errCommit) => {
          if (errCommit) {
            console.error('Commit error:', errCommit);
            return db.rollback(() => res.status(500).json({ error: 'Failed to commit transaction' }));
          }
          return res.json({ success: true, updated: results.length });
        });
      })
      .catch((errAny) => {
        db.rollback(() => {
          console.error('Rollback due to error:', errAny);
          return res.status(500).json({ error: 'Failed to process attendance records', details: errAny.message });
        });
      });
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
