const mysql = require('mysql2');

const connection = mysql.createConnection({
    host: 'b43vmkmobgmqtsuy6pje-mysql.services.clever-cloud.com',
    port: '3306',
    user: 'ujd22pfszi18xqwv',
    password: 'ClpZKevHxi8QfbZftYoJ',
    database: 'b43vmkmobgmqtsuy6pje'
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
