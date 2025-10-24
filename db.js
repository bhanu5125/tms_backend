const mysql = require('mysql2');

const connection = mysql.createPool({
    host: 'mysql.trafficcounting.in',
    port: '3306',
    user: 'traffic_tcs_test',
    password: 'Htpl@123',
    database: 'traffic_tcs_test',
    waitForConnections: true,
    multipleStatements: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Connect to MySQL
connection.getConnection((err, con) => {
    if (err) {
        console.error('Error connecting to MySQL:', err.message);
    } else {
        console.log('Connected to MySQL database via pool!');
        con.release(); // release to pool
    }
});

module.exports = connection;