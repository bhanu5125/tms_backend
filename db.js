const mysql = require('mysql2');

const connection = mysql.createConnection({
    host: 'localhost',
    port: '7777',
    user: 'root',
    password: 'bhanu5125',
    database: 'traffic_sms_test'
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
