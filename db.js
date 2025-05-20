const mysql = require('mysql2');

const connection = mysql.createConnection({
    host: 'database-1.cqj8amwoqe29.us-east-1.rds.amazonaws.com',
    port: '3306',
    user: 'admin',
    password: 'Bhanu$12$',
    database: 'sms',
    waitForConnections: true,
    multipleStatements: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Connect to MySQL
connection.connect((err) => {
    if (err) {
        console.error('Error connecting to MySQL:', err.message);
        return;
    }
    console.log('Connected to MySQL database!');
});

module.exports = connection;
