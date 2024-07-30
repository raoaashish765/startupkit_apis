const express = require('express');
const app = express();
const cors = require('cors');
const bodyParser = require('body-parser');
const path = require('path');
const fs = require('fs');
const https = require('https');
const querystring = require('querystring');

const nodemailer = require('nodemailer')
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const randomColor = require('randomcolor');


// Serve static files from the 'public' directory
app.use("/public", express.static('public'));


const mysql = require('mysql2');

// Allow all CORS requests
app.use(cors());

// Parse JSON bodies
app.use(bodyParser.json());

// Parse URL-encoded bodies
app.use(bodyParser.urlencoded({ extended: true }));


// const pool = mysql.createPool({
//     host: 'localhost',
//     user: 'root',
//     password: '',
//     database: 'vue_database'
// }).promise();

// const pool = mysql.createPool({
//     host: `216.10.242.140`,
//     user: `wipsite_startupkit`,
//     password: `NWYV!(ymnNVU`,
//     database: `wipsite_startupkit_react`,
//     // port: 3306
// }).promise();

let pool;
try {
    pool = mysql.createPool({
        host: '216.10.242.140',
        user: 'wipsite_startupkit',
        password: 'NWYV!(ymnNVU',
        database: 'wipsite_startupkit_react',
        waitForConnections: true,
        connectionLimit: 10,
        queueLimit: 0,
        connectTimeout: 10000,
    }).promise();

    console.log('Database pool created successfully.');
} catch (error) {
    console.error('Error creating database pool:', error);
    // Optionally, handle the error further or exit the process
    process.exit(1); // Exit with failure code
}

// const result = await pool.query("SELECT * FROM vue_database")
// console.log(result);

async function getsql() {
    const result = await pool.query("SELECT * FROM users")
    return result;
}

const port = 8000;
const host = '0.0.0.0';



app.listen(port, host, () => {
    console.log(`server started on port: ${port}`);
})

app.get('/', (req, res) => {
    res.send('Welcome.. server running!!');
});
app.get('/users', async (req, res) => { // Add async here
    try {
        const result = await getsql(); // Call the async function getsql() here
        res.send(result[0]);
    } catch (error) {
        console.error(error);
        res.status(500).send('Internal Server Error');
    }
});

// Route to fetch page data for the home page
// app.get('/pages/home', async (req, res) => {
//     try {
//         const [rows] = await pool.query('SELECT * FROM pages WHERE page_name = ?', ['home']);

//         if (rows.length === 0) {
//             res.status(404).json({ message: 'Page not found' });
//         } else {
//             res.json(rows[0]);
//         }
//     } catch (error) {
//         console.error('Error fetching page data:', error);
//         res.status(500).json({ message: 'Internal server error' });
//     }
// });

// Route to fetch clients data for the home page
// app.get('/sections/clients', async (req, res) => {
//     try {
//         const [rows] = await pool.query('SELECT * FROM sections WHERE section_name = ?', ['clients']);

//         if (rows.length === 0) {
//             res.status(404).json({ message: 'Page not found' });
//         } else {
//             res.json(rows[0]);
//         }
//     } catch (error) {
//         console.error('Error fetching page data:', error);
//         res.status(500).json({ message: 'Internal server error' });
//     }
// });
// app.get('/sections/slider', async (req, res) => {
//     try {
//         const [rows] = await pool.query('SELECT * FROM sections WHERE section_name = ?', ['slider']);

//         if (rows.length === 0) {
//             res.status(404).json({ message: 'Page not found' });
//         } else {
//             console.log(rows[0]);
//             res.json(rows[0]);
//         }
//     } catch (error) {
//         console.error('Error fetching page data:', error);
//         res.status(500).json({ message: 'Internal server error' });
//     }
// });
// app.get('/sections/services', async (req, res) => {
//     try {
//         const [rows] = await pool.query('SELECT * FROM sections WHERE section_name = ?', ['services']);

//         if (rows.length === 0) {
//             res.status(404).json({ message: 'Page not found' });
//         } else {
//             console.log(rows[0]);
//             res.json(rows[0]);
//         }
//     } catch (error) {
//         console.error('Error fetching page data:', error);
//         res.status(500).json({ message: 'Internal server error' });
//     }
// });

app.get('/pages/:pageid', async (req, res) => {
    const pageid = req.params.pageid; // Get secid from URL parameter

    try {
        const [rows] = await pool.query('SELECT * FROM pages WHERE page_name = ?', [pageid]);

        if (rows.length === 0) {
            res.status(404).json({ message: 'Section not found' });
            // console.log("no section found");
        } else {
            res.json(rows[0]);
            // console.log("done...");
        }
    } catch (error) {
        console.error('Error fetching section data:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.get('/sections/:secid', async (req, res) => {
    const secid = req.params.secid; // Get secid from URL parameter

    try {
        const [rows] = await pool.query('SELECT * FROM sections WHERE section_name = ?', [secid]);

        if (rows.length === 0) {
            res.status(404).json({ message: 'Section not found' });
            // console.log("no section found");
        } else {
            res.json(rows[0]);
            // console.log("done...");
        }
    } catch (error) {
        console.error('Error fetching section data:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});



app.post('/login', async (req, res) => {
    try {
        // Extract user data from request body
        const { the_username, password } = req.body;

        // Check if all required fields are present
        if (!the_username || !password) {
            console.log("all fields not present.......");
            return res.status(400).json({ message: "Please provide all required fields." });
        }

        // Check if passwords match and meet the criteria
        if (!isValidPassword(password)) {
            console.log("Confirm password didn't match or password criteria not met.......");
            return res.status(400).json({ message: "Confirm password didn't match or password criteria not met." });
        }

        // Function to check password criteria
        function isValidPassword(password) {
            // Password criteria: minimum length 8, include alphanumeric and special character,
            // must include 1 uppercase, 1 lowercase, 1 number, and 1 special character
            const passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[^a-zA-Z0-9])(?=.*[a-zA-Z0-9]).{8,}$/;
            return passwordRegex.test(password);
        }


        // Check if username or email already exists in the database
        const [existingUsers] = await pool.query(
            'SELECT * FROM users WHERE username = ?',
            [the_username]
        );

        if (existingUsers.length == 0) {
            console.log("User didn't exists.......");
            console.log(existingUsers.length);
            return res.status(400).json({ message: "User didn't exists." });
        }

        if (existingUsers[0].verification_status == 'unverified') {
            console.log("verfication required.......");
            console.log(existingUsers.length);
            return res.status(400).json({ message: "verfication required." });
        }
        if (existingUsers[0].account_status != 'active') {
            console.log("Unfortunately your account is suspended.......");
            console.log(existingUsers.length);
            return res.status(400).json({ message: "Unfortunately your account is suspended." });
        }
        if (existingUsers[0].password != password) {
            console.log("Password is incorrect.......");
            console.log(existingUsers.length);
            return res.status(400).json({ message: "Password is incorrect." });
        }
        const usr_role = existingUsers[0].role;

        const secretKey = crypto.randomBytes(32).toString('hex');
        const token = jwt.sign({ the_username, usr_role }, secretKey, { expiresIn: '24h' });

        await pool.query(
            'UPDATE users SET api_token = ? WHERE username = ?',
            [token, existingUsers[0].username]
        );

        console.log("login complete..");
        console.log(token);
        const ipAddress = req.ip;
        console.log(ipAddress);

        res.status(201).json({ token, message: "User login successfully." });
    } catch (error) {
        console.error(error);
        console.log("error occured..");
        res.status(500).json({ message: "Internal Server Error" });
    }
});


app.post('/verify/:vtoken', async (req, res) => {
    try {
        const vtoken = req.params.vtoken;

        // Check if the provided API secret exists
        const [existingUsers] = await pool.query(
            'SELECT * FROM users WHERE api_secret = ?',
            [vtoken]
        );

        if (existingUsers.length === 0) {
            return res.status(404).json({ message: "API secret not found." });
        }

        // Assuming there's only one user with this API secret, otherwise, you may need to handle it differently
        const user = existingUsers[0];

        // Check if the verification status is 'unverified'
        if (user.verification_status === 'unverified') {
            // Update verification status to 'verified'
            console.log(user);
            await pool.query(
                'UPDATE users SET verification_status = ? WHERE user_id = ?',
                ['verified', user.user_id]
            );

            return res.status(200).json({ message: "Verification successful." });
        } else {
            return res.status(400).json({ message: "User is already verified." });
        }
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Internal Server Error" });
    }
});

app.post('/components/test', async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT * FROM components WHERE component_name = ?', ['test']);

        if (rows.length === 0) {
            console.log('no data');
            return res.status(404).json({ message: 'Page not found' });
        } else {
            console.log(rows[0]);
            return res.json(rows[0]);
        }
    } catch (error) {
        console.error('Error fetching page data:', error);
        return res.status(500).json({ message: 'Internal server error' });
    }
});

const roleshierarchy = {
    'superadmin': ['company', 'team', 'agent', 'client'],
    'company': ['team', 'agent', 'client'],
    'team': ['agent', 'client'],
    'agent': ['client'],
    'client': []
};


app.post('/api/register', async (req, res) => {
    try {
        // Extract user data from request body
        const { u_name, the_name, the_email, password, password2, userType, creatorToken } = req.body;

        console.log(u_name, the_name, the_email, password, password2, userType, creatorToken);

        // Check for user role and permission
        const [permisioncheck] = await pool.query(
            'SELECT * FROM users WHERE api_token = ?',
            [creatorToken]
        );
        if (permisioncheck.length !== 1 || permisioncheck[0].role !== 'superadmin') {
            console.log("token or role not match");
            return res.status(400).json({ message: "Something Went Wrong, Your Account Is not Authorized! Please Log In Again" });
        }

        // Check if all required fields are present
        if (!the_name || !the_email || !password || !password2) {
            console.log("all fields not present.......");
            return res.status(400).json({ message: "Please provide all required fields." });
        }
        // Check if name contains only letters and spaces with a minimum length of 5
        if (!/^[a-zA-Z\s]{5,}$/.test(the_name)) {
            console.log("name should be only letters and spaces, minimum length 5.......");
            return res.status(400).json({ message: "Name should be only letters and spaces with a minimum length of 5." });
        }

        // Check if the email format is valid
        if (!/\S+@\S+\.\S+/.test(the_email)) {
            console.log("email not correct .......");
            return res.status(400).json({ message: "Email format is not correct." });
        }

        // Check if passwords match and meet the criteria
        if (password !== password2 || !isValidPassword(password)) {
            console.log("Confirm password didn't match or password criteria not met.......");
            return res.status(400).json({ message: "Confirm password didn't match or password criteria not met." });
        }

        // Function to check password criteria
        function isValidPassword(password) {
            // Password criteria: minimum length 8, include alphanumeric and special character,
            // must include 1 uppercase, 1 lowercase, 1 number, and 1 special character
            const passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[^a-zA-Z0-9])(?=.*[a-zA-Z0-9]).{8,}$/;
            return passwordRegex.test(password);
        }

        // Check if username or email already exists in the database
        const [existingUsers] = await pool.query(
            'SELECT * FROM users WHERE username = ? OR email = ?',
            [the_name, the_email]
        );

        if (existingUsers.length > 0) {
            console.log("Username or email already exists.......");
            return res.status(400).json({ message: "Username or email already exists." });
        }

        const verify_token = crypto.randomBytes(32).toString('hex');

        // Insert user data into the database
        const result = await pool.query(
            'INSERT INTO users (name, username, email, password, api_secret) VALUES (?, ?, ?, ?, ?)',
            [u_name, the_name, the_email, password, verify_token]
        );

        console.log(result);

        const [theres] = await pool.query("SELECT * FROM users WHERE user_id = ?", [result[0].insertId]);

        console.log(theres);

        console.log("registration complete, please verify email..");
        return res.status(200).json({ data: theres[0], message: "User registered successfully. verify your email to login." });
    } catch (error) {
        console.error(error);
        console.log("error occured..");
        res.status(500).json({ message: "Internal Server Error" });
    }
});

app.post('/useraction/verifyuser', async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT * FROM users WHERE verification_status = ?', ['unverified']);

        if (rows.length === 0) {
            res.status(404).json({ message: 'Page not found' });
        } else {
            console.log(rows);
            res.json(rows);
        }
    } catch (error) {
        console.error('Error fetching page data:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});


// Route to fetch clients data for the home page
app.get('/editpageall', async (req, res) => {
    try {

        const [rows] = await pool.query('SELECT * FROM pages');

        if (rows.length === 0) {
            res.status(404).json({ message: 'Page not found' });
        } else {
            res.json(rows);
        }
    } catch (error) {
        console.error('Error fetching page data:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});
app.get('/singleeditpage/:id', async (req, res) => {
    const { id } = req.params;

    try {
        const [rows] = await pool.query('SELECT * FROM pages WHERE id = ?', [id]);

        if (rows.length === 0) {
            res.status(404).json({ message: 'Page not found' });
        } else {
            res.json(rows[0]); // Assuming you only expect one page with the given ID
        }
    } catch (error) {
        console.error('Error fetching page data:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});
app.post('/singleupdatepage/:id', async (req, res) => {
    const { id } = req.params;
    const updatedData = req.body;
    console.log(id);

    try {
        const contentString = JSON.stringify(updatedData.content);
        console.log(contentString);
        await pool.query('UPDATE pages SET content = ? WHERE id = ?', [contentString, id]);
        res.status(200).json({ message: 'Page data updated successfully' });
    } catch (error) {
        console.error('Error updating page data:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});
app.post('/showserverimgs', async (req, res) => {

    try {
        const imgDir = path.join(__dirname, 'public', 'img');
        fs.readdir(imgDir, (err, files) => {
            if (err) {
                throw err;
            }
            const imgUrls = files.map(file => `/public/img/${file}`).reverse();
            res.json(imgUrls);
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});


app.get('/editsectionall', async (req, res) => {
    try {

        const [rows] = await pool.query('SELECT * FROM sections');

        if (rows.length === 0) {
            res.status(404).json({ message: 'Page not found' });
        } else {
            res.json(rows);
        }
    } catch (error) {
        console.error('Error fetching page data:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});
app.get('/singleeditsection/:id', async (req, res) => {
    const { id } = req.params;

    try {
        const [rows] = await pool.query('SELECT * FROM sections WHERE id = ?', [id]);

        if (rows.length === 0) {
            res.status(404).json({ message: 'Page not found' });
        } else {
            res.json(rows[0]); // Assuming you only expect one page with the given ID
        }
    } catch (error) {
        console.error('Error fetching page data:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});
app.post('/singleupdatesection/:id', async (req, res) => {
    const { id } = req.params;
    const updatedData = req.body;
    console.log(id);

    try {
        const contentString = JSON.stringify(updatedData.content);
        console.log(contentString);
        await pool.query('UPDATE sections SET content = ? WHERE id = ?', [contentString, id]);
        res.status(200).json({ message: 'Page data updated successfully' });
    } catch (error) {
        console.error('Error updating page data:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});


app.post('/api/login', async (req, res) => {
    // Check credentials
    const { email, password } = req.body;
    console.log(email, password);
    // Check if username or email already exists in the database
    const [existingUsers] = await pool.query(
        'SELECT * FROM users WHERE username = ? OR email = ?',
        [email, email]
    );

    if (existingUsers.length == 0) {
        console.log("User didn't exists.......");
        console.log(existingUsers.length);
        return res.status(401).json({ data: { errors: "User didn't exists.", loggedin: false } });
    }

    // if (existingUsers[0].verification_status == 'unverified') {
    //     console.log("verfication required.......");
    //     console.log(existingUsers.length);
    //     return res.status(500).json({ data: { errors: "verfication required.", loggedin: false } });
    // }
    if (existingUsers[0].account_status != 'active') {
        console.log("Unfortunately your account is suspended.......");
        console.log(existingUsers.length);
        return res.status(500).json({ data: { errors: "Unfortunately your account is suspended.", loggedin: false } });
    }
    if (existingUsers[0].password != password) {
        console.log("Password is incorrect.......");
        console.log(existingUsers.length);
        return res.status(401).json({ data: { errors: "Password is incorrect.", loggedin: false } });
    }

    const secretKey = crypto.randomBytes(32).toString('hex');
    const token = jwt.sign({ email }, secretKey, { expiresIn: '24h' });

    await pool.query(
        'UPDATE users SET api_token = ? WHERE username = ? OR email = ?',
        [token, existingUsers[0].username, existingUsers[0].username]
    );

    // Successful login
    res.status(200).json({
        data: {
            data: {
                email: email,
                password: password,
                token: token,
                role: existingUsers[0].role,
                profilepic: existingUsers[0].profile_picture,
                id: existingUsers[0].user_id,
            },
            loggedin: true, success: "Login was successfully !"
        }
    });


});

app.get('/api/allpagelisting', async (req, res) => {
    try {

        const [rows] = await pool.query('SELECT * FROM pages');

        if (rows.length === 0) {
            res.status(404).json({ message: 'Page not found' });
        } else {
            console.log("request sent back");
            // console.log(rows);
            res.json(rows);
        }
    } catch (error) {
        console.error('Error fetching page data:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.post('/api/pages/:pageid', async (req, res) => {
    const { pageid } = req.params;
    const accessToken = req.headers['access-token'];
    const username = req.headers['user'];
    console.log(accessToken, username);
    try {
        const [auth] = await pool.query('SELECT * FROM users WHERE username = ? AND api_token = ?', [username, accessToken]);
        console.log(auth.length);
        console.log(auth);
        if (auth.length === 0 || auth.length > 1) {
            return res.status(500).json({ message: 'Internal server error' });
        }

        const contentAsJson = JSON.stringify(req.body.content);
        console.log("contentas json", contentAsJson);
        const thepage = await pool.query('SELECT * FROM pages WHERE id = ?', [pageid]);
        console.log(thepage[0][0].url);
        console.log(req.body.datapg[4]);
        await pool.query(
            'UPDATE pages SET content = ?, modified_by = ? WHERE id = ?',
            [contentAsJson, username, pageid]
        );

        //check if url is modified
        if (thepage[0][0].url !== req.body.datapg[4]) {
            const links = await pool.query('SELECT GROUP_CONCAT(url SEPARATOR \',\') AS urls FROM pages');
            const urlsString = links[0][0].urls
            const urlsArray = urlsString.split(',');
            console.log(urlsArray);
            if (urlsArray.includes(req.body.datapg[4])) {
                return res.status(500).json({ message: 'Internal server error' });
            }
            await pool.query(
                'UPDATE pages SET url = ? WHERE id = ?',
                [req.body.datapg[4], pageid]
            );
        }
        res.status(200).json({ message: 'success' });
    } catch (error) {
        console.error('Error fetching page data:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.get('/api/allimages', (req, res) => {
    const directoryPath = path.join(__dirname, 'public/img');

    fs.readdir(directoryPath, (err, files) => {
        if (err) {
            return res.status(500).send('Unable to scan directory');
        }
        // Filter files to include only image files (basic filtering)
        const images = files.filter(file => /\.(jpg|jpeg|png|gif|mp4)$/i.test(file)).reverse();
        res.json(images);
    });
});

app.get('/api/dashdata', async (req, res) => {
    try {
        const totalVisitorQuery = 'SELECT COUNT(*) AS totalVisitor FROM visitordata';
        const uniqueSessionsQuery = 'SELECT COUNT(DISTINCT visitor_ip) AS uniqueSessions FROM visitordata';

        const [totalVisitorResult] = await pool.query(totalVisitorQuery);
        const [uniqueSessionsResult] = await pool.query(uniqueSessionsQuery);

        const totalVisitor = totalVisitorResult[0].totalVisitor;
        const uniqueSessions = uniqueSessionsResult[0].uniqueSessions;

        console.log(totalVisitor, uniqueSessions);
        res.json({ totalVisitor, uniqueSessions });
    } catch (error) {
        console.error('Error fetching page data:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.get('/api/visitorchart', async (req, res) => {
    console.log("request received!!");
    // const currentDate = new Date();
    var currentDate = new Date();

    const formatDate = (date) => {
        // Format the date to YYYY-MM-DD
        const formattedDate = date.toISOString().slice(0, 10);
        return formattedDate;
    };
    const todayStartFormatted = formatDate(currentDate);

    try {
        // Query for today's data
        const todayData = await pool.query(`SELECT HOUR(date) AS hour, COUNT(*) AS users 
        FROM visitordata 
        WHERE DATE(date) >= ? 
        GROUP BY hour;
        `, [todayStartFormatted]);

        const today = {
            users: Array.from({ length: 24 }, () => 0),
            labels: Array.from({ length: 24 }, (_, i) => `${i}(h)`)
        };

        todayData[0].forEach(row => {
            const index = row.hour;
            today.users[index] = row.users;
        });

        const weekData = await pool.query(`SELECT DATE_FORMAT(date, '%Y-%m-%d') AS day, COUNT(*) AS users 
        FROM visitordata 
        WHERE date >= DATE_SUB(?, INTERVAL 7 DAY) 
        GROUP BY day;`, [todayStartFormatted]);

        const week = {
            users: Array.from({ length: 7 }, () => 0),
            labels: Array.from({ length: 7 }, (_, i) => {
                const indexdate = new Date(new Date(todayStartFormatted).getTime() - i * 24 * 60 * 60 * 1000).toISOString().split('T')[0];
                return indexdate;
            }).reverse()
        };

        weekData[0].forEach(row => {
            const dayIndex = week.labels.indexOf(row.day);
            week.users[dayIndex] = row.users;
        });
        week.labels[6] = 'Today';
        week.labels[5] = 'Yesterday';

        const sixMonthsAgo = new Date(currentDate);
        sixMonthsAgo.setMonth(currentDate.getMonth() - 5);
        const sixMonthsAgoFormatted = formatDate(sixMonthsAgo);

        const monthData = await pool.query(`SELECT DATE_FORMAT(date, '%Y-%m') AS month, COUNT(*) AS users
        FROM visitordata
        WHERE date >= ? AND date < ?
        GROUP BY month;
    `, [sixMonthsAgoFormatted, todayStartFormatted]);

        const labels = [];
        for (let i = 4; i >= -1; i--) {
            const indexMonth = new Date(currentDate.getFullYear(), currentDate.getMonth() - i, 1);
            labels.push(indexMonth.toISOString().split('T')[0].substring(0, 7));
        }

        const month = {
            users: Array.from({ length: 6 }, () => 0),
            labels: labels
        };

        monthData[0].forEach(row => {
            const monthIndex = month.labels.indexOf(row.month);
            if (monthIndex !== -1) {
                month.users[monthIndex] = row.users;
            }
        });

        // Combine the data into the desired structure
        const result = {
            today,
            week,
            month
        };

        // Send the result as JSON
        res.json(result);

    } catch (error) {
        console.error('Error fetching page data:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.get('/api/visitorbycountry', async (req, res) => {
    try {
        const [rows] = await pool.query(`SELECT visitor_country, COUNT(*) as count 
      FROM visitordata 
      WHERE DATE_FORMAT(date, '%Y-%m') = DATE_FORMAT(CURRENT_DATE(), '%Y-%m')
      GROUP BY visitor_country 
      ORDER BY count DESC
      LIMIT 9`);

        const labels = rows.map(row => row.visitor_country);
        const data = rows.map(row => row.count);
        const backgroundColor = data.map(() => randomColor({ luminosity: 'bright' }));

        const response = {
            labels: labels,
            datasets: [
                {
                    data: data,
                    backgroundColor: backgroundColor,
                },
            ],
        };
        console.log(response);

        res.json(response);
    } catch (error) {
        console.error('Error fetching visitor data by country:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.get('/api/allseclisting', async (req, res) => {
    try {

        const [rows] = await pool.query('SELECT * FROM sections');

        if (rows.length === 0) {
            res.status(404).json({ message: 'Page not found' });
        } else {
            console.log("request sent back");
            // console.log(rows);
            res.json(rows);
        }
    } catch (error) {
        console.error('Error fetching page data:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});
app.post('/api/sec/:secid', async (req, res) => {
    const { secid } = req.params;
    try {
        const contentAsJson = JSON.stringify(req.body.content);
        await pool.query(
            'UPDATE sections SET content = ? WHERE id = ?',
            [contentAsJson, secid]
        );
        res.status(200).json({ message: 'success' });
    } catch (error) {
        console.error('Error fetching page data:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});
app.post('/newvisitor', async (req, res) => {
    const { country, ip, pageid } = req.body;
    const currentDate = new Date();
    try {
        const result = await pool.query(
            'INSERT INTO visitordata (page_id, visitor_country, visitor_ip, date) VALUES (?, ?, ?, ?)',
            [pageid, country, ip, currentDate]
        );
        const insertedId = result[0].insertId;
        console.log(country, ip, pageid, insertedId);
        res.status(200).json({ id: insertedId });
    } catch (error) {
        console.error('Error fetching page data:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});
app.post('/upvisitortime', async (req, res) => {
    const { insertedid, time } = req.body;
    try {
        const result = await pool.query(
            'UPDATE visitordata SET visit_duration = ? WHERE id = ?',
            [time, insertedid]
        );
        console.log(result);
        res.status(200).json({ message: "success" });
    } catch (error) {
        console.error('Error fetching page data:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

var theCurrDate = Date.now();

const multer = require('multer');
const { log } = require('console');
// Multer configuration
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, './public/img'); // Destination folder for storing files
    },
    filename: function (req, file, cb) {
        // Use the generated timestamp for unique filename
        const uniqueFileName = `uploads-${req.theCurrDate}-${file.originalname}`;
        req.generatedFileName = uniqueFileName; // Store filename in request object
        cb(null, uniqueFileName); // Callback with filename
    }
});
const upload = multer({ storage: storage });

app.post('/api/upimage', (req, res, next) => {
    req.theCurrDate = Date.now();
    next();
}, upload.fields([{ name: 'image', maxCount: 1 }, { name: 'video', maxCount: 1 }]), async (req, res) => {
    try {
        const files = req.files;

        if (!files || Object.keys(files).length === 0) {
            return res.status(400).json({ message: 'No files uploaded' });
        }

        let uploadedFiles = {};

        // Check if image file is uploaded
        if (files.image && files.image.length > 0) {
            uploadedFiles = req.theCurrDate; // Assuming you want to store the generated filename
        }

        // Check if video file is uploaded
        if (files.video && files.video.length > 0) {
            uploadedFiles = req.theCurrDate; // Assuming you want to store the generated filename
        }

        console.log('Uploaded files:', uploadedFiles);

        // Respond with the uploaded file details
        res.status(200).json({
            message: 'Files uploaded successfully',
            data: uploadedFiles,
            files: req.files  // Optional: Return all files for debugging purposes
        });
    } catch (error) {
        console.error('Error uploading files:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});


// app.post('/api/upimage', (req, res, next) => {
//     req.theCurrDate = Date.now();
//     next();
// }, upload.array('image', 50), async (req, res) => {
//     try {
//         const files = req.files;
//         console.log(files);

//         if (!files || files.length === 0) {
//             return res.status(400).json({ message: 'No files uploaded' });
//         }

//         // Array to store uploaded file details
//         let uploadedFiles;

//         // Construct response array with filenames
//         files.forEach(file => {
//             uploadedFiles = req.theCurrDate;
//         });

//         console.log('Uploaded files:', uploadedFiles);

//         // Respond with the array of uploaded file details
//         res.status(200).json({ message: 'Files uploaded successfully', data: uploadedFiles, files: files });
//     } catch (error) {
//         console.error('Error uploading files:', error);
//         res.status(500).json({ message: 'Internal server error' });
//     }
// });



app.post('/api/deleteimage', async (req, res) => {
    const { filename } = req.body;
    try {
        const filePath = path.join(__dirname, 'public/img/', filename);
        console.log(filePath);
        fs.access(filePath, fs.constants.F_OK, (err) => {
            if (err) {
                console.error('File not found:', err);
                return res.status(404).json({ message: 'File not found.' });
            }

            // Delete the file
            fs.unlink(filePath, (err) => {
                if (err) {
                    console.error('Failed to delete the file:', err);
                    return res.status(500).json({ message: 'Failed to delete the file.' });
                }

                console.log('File deleted successfully.');
                res.status(200).json({ message: 'File deleted successfully.' });
            });
        });
    } catch (error) {
        console.error('Error fetching page data:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.get('/api/menupagedata', async (req, res) => {
    try {

        const [rows] = await pool.query('SELECT * FROM menudata');
        const [rowspages] = await pool.query('SELECT * FROM pages');

        if (rows.length === 0) {
            res.status(404).json({ message: 'Page not found' });
        } else {
            console.log("request sent back");
            // console.log(rows);
            res.json({ 'rows': rows, 'links': rowspages });
        }
    } catch (error) {
        console.error('Error fetching page data:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.post('/api/menuupdate', async (req, res) => {
    try {
        const contentAsJson = JSON.stringify(req.body.content);
        await pool.query(
            'UPDATE menudata SET content = ? WHERE id = 1',
            [contentAsJson]
        );
        res.status(200).json({ message: 'success' });
    } catch (error) {
        console.error('Error fetching page data:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.get('/api/settingsdata', async (req, res) => {
    try {

        const [rows] = await pool.query('SELECT * FROM site_settings');

        if (rows.length === 0) {
            res.status(404).json({ message: 'Page not found' });
        } else {
            console.log(rows);
            res.json(rows);
        }
    } catch (error) {
        console.error('Error fetching page data:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.post('/api/settingsupdate', async (req, res) => {
    try {
        const settings = req.body.content;

        // Ensure the content is an array
        if (!Array.isArray(settings)) {
            return res.status(400).json({ message: 'Invalid content format' });
        }

        // Iterate through the array and update each row
        for (const setting of settings) {
            const { id, setting_value } = setting;

            await pool.query(
                'UPDATE site_settings SET setting_value = ? WHERE id = ?',
                [setting_value, id]
            );
        }

        res.status(200).json({ message: 'success' });
    } catch (error) {
        console.error('Error fetching page data:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.get('/menupagedata', async (req, res) => {
    try {

        const [rows] = await pool.query('SELECT * FROM menudata');
        const [rowspages] = await pool.query('SELECT * FROM site_settings');

        if (rows.length === 0) {
            res.status(404).json({ message: 'Page not found' });
        } else {
            console.log("request sent back");
            // console.log(rows);
            res.json({ 'rows': rows, 'settings': rowspages });
        }
    } catch (error) {
        console.error('Error fetching page data:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.post('/api/submitform', async (req, res) => {
    try {
        const formdata = req.body;

        // Extract data from formdata
        const { name, phone, email, services, message } = formdata;
        const user_ip = req.ip; // Assuming this gets the user's IP address

        // Insert data into the database
        const insertQuery = `
            INSERT INTO form_submit (name, phone, email, service, message, user_ip)
            VALUES (?, ?, ?, ?, ?, ?)
        `;
        const insertValues = [name, phone, email, services, message, user_ip];
        await pool.query(insertQuery, insertValues);

        res.status(200).json({ message: 'success' });
    } catch (error) {
        console.error('Error inserting form data:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});



app.get('/api/workcategorydata', async (req, res) => {
    try {

        const [rows] = await pool.query('SELECT * FROM category_work');

        console.log(rows);
        res.json(rows);
    } catch (error) {
        console.error('Error fetching page data:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});
app.post('/api/workcategoryadd', async (req, res) => {
    try {
        console.log("adding category");
        const addedname = req.body.content;
        const addedimg = req.body.catimage;
        const username = req.headers['user'];

        // Insert into the database
        await pool.query(
            'INSERT INTO category_work (name, created_by, image_url) VALUES (?, ?, ?)',
            [addedname, username, addedimg]
        );

        // Query the newly inserted row
        const result = await pool.query(
            'SELECT * FROM category_work WHERE name = ? AND created_by = ?',
            [addedname, username]
        );

        // Extract the inserted row from the result
        const insertedRow = result[0];

        // Return success message and the newly added row
        res.status(200).json({
            message: 'success',
            data: insertedRow[0]
        });

    } catch (error) {
        console.error('Error adding category:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});
app.post('/api/workcategorydel', async (req, res) => {
    try {
        console.log("deleting category");
        const delid = req.body.content;

        // delete the category from database
        await pool.query(
            'DELETE FROM category_work WHERE id = ?',
            [delid]
        );

        // Return success message and the newly added row
        res.status(200).json({
            message: 'success',
        });

    } catch (error) {
        console.error('Error adding category:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});
app.post('/api/workcategoryup', async (req, res) => {
    try {
        console.log("updating category");
        const newname = req.body.upcontent;

        // Update the name in the database
        // await pool.query(
        //     'UPDATE category_work SET name = ? WHERE id = ?',
        //     [newname[1], newname[0]]
        // );
        await pool.query(
            'UPDATE category_work SET name = ?, image_url = ? WHERE id = ?',
            [newname[1], newname[4], newname[0]]
        );

        // Return success message and the newly added row
        res.status(200).json({
            message: 'success',
        });

    } catch (error) {
        console.error('Error adding category:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});



app.get('/api/workprojectdata', async (req, res) => {
    try {

        const [rows] = await pool.query('SELECT * FROM work_projects');

        console.log(rows);
        res.json(rows);
    } catch (error) {
        console.error('Error fetching page data:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});
app.post('/api/workprojectadd', async (req, res) => {
    try {
        console.log("adding category");
        const addedname = req.body.content;
        console.log(addedname[0].name);
        const username = req.headers['user'];

        // Insert into the database
        const insertResult = await pool.query(
            'INSERT INTO work_projects (name, created_by, updated_by, description, image_url, image_url2, category) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [addedname[0].name, username, username, addedname[0].description, addedname[0].image1, addedname[0].image2, addedname[0].category]
        );

        console.log('Insert Result:', insertResult);

        // Get the ID of the newly inserted row
        const newId = insertResult.insertId || insertResult[0]?.insertId;
        console.log('New ID:', newId);

        if (newId) {
            // Query the newly inserted row using the ID
            const result = await pool.query(
                'SELECT * FROM work_projects WHERE id = ?',
                [newId]
            );

            // Extract the inserted row from the result
            const insertedRow = result[0];
            console.log('Inserted Row:', insertedRow);

            // Use insertedRow for further operations
            // Example: handle adding category
            // Return success message and the newly added row
            res.status(200).json({
                message: 'success',
                data: insertedRow[0]
            });
        } else {
            console.error('No ID found for the inserted row.');
            // Return success message and the newly added row
            res.status(500).json({
                message: 'Server error'
            });
        }
    } catch (error) {
        console.error('Error adding category:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});
app.post('/api/workprojectdel', async (req, res) => {
    try {
        console.log("deleting category");
        const delid = req.body.content;

        // delete the category from database
        await pool.query(
            'DELETE FROM work_projects WHERE id = ?',
            [delid]
        );

        // Return success message and the newly added row
        res.status(200).json({
            message: 'success',
        });

    } catch (error) {
        console.error('Error adding category:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});
app.post('/api/workprojectup', async (req, res) => {
    try {
        console.log("updating project");
        const updatedProject = req.body.contentup[4];
        console.log(updatedProject);
        const username = req.headers['user'];


        // Update into the database
        await pool.query(
            'UPDATE work_projects SET name = ?, updated_by = ?, description = ?, image_url = ?, image_url2 = ?, category = ? WHERE id = ?',
            [updatedProject.name, username, updatedProject.description, updatedProject.image_url, updatedProject.image_url2, updatedProject.category, updatedProject.id]
        );

        res.status(200).json({
            message: 'success'
        });
    } catch (error) {
        console.error('Error updating project:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.post('/api/forgotpass', async (req, res) => {
    const { values } = req.body;
    console.log(values);

    try {
        // Check if username or email already exists in the database
        const [existingUsers] = await pool.query(
            'SELECT * FROM users WHERE username = ? OR email = ?',
            [values.email, values.email]
        );
        if (existingUsers.length == 0 || existingUsers.length > 1) {
            console.error('Error sending email:', error);
            res.status(500).json({ message: 'Internal server error' });
        }
        console.log(existingUsers[0]);

        const to = existingUsers[0].email;
        const subject = "Merastartup kit Admin Password Recovery";
        // const message = "Your password is "+ existingUsers[0].api_secret.slice(0, 16);
        const message = "Your password is " + existingUsers[0].password;
        const postData = querystring.stringify({
            to: to,
            subject: subject,
            message: message
        });
        console.log(postData);

        const options = {
            hostname: 'wipsite.in', // Replace with your actual domain (without https://)
            path: '/demo/reactphp/forgotpass.php', // Replace with your actual PHP script path
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Content-Length': Buffer.byteLength(postData)
            }
        };
        const req = https.request(options, (res) => {
            console.log(`Status Code: ${res.statusCode}`);

            res.setEncoding('utf8');
            res.on('data', (chunk) => {
                console.log(`Response Body: ${chunk}`);
            });

            res.on('end', () => {
                console.log('No more data in response.');
            });
        });

        req.on('error', (e) => {
            console.error(`Problem with request: ${e.message}`);
        });

        // Write data to request body
        req.write(postData);
        req.end();

        res.status(200).json({ message: 'success' });
    } catch (error) {
        console.error('Error sending email:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});




app.post('/api/useraccsetting', async (req, res) => {
    try {
        const accessToken = req.headers['access-token'];
        const username = req.headers['user'];
        console.log(accessToken, username);

        // Adjusted query to fetch specific user based on username and api_token
        const [rows] = await pool.query('SELECT * FROM users WHERE username = ? AND api_token = ?', [username, accessToken]);

        rows[0].password = "";
        rows[0].api_token = "";
        rows[0].api_secret = "";

        console.log(rows);
        res.json(rows);
        // wss.clients.forEach(client => {
        //     console.log(client);
        //     // if (client.readyState === WebSocket.OPEN) {
        //     //     client.send(JSON.stringify(rows));
        //     // }
        // });
    } catch (error) {
        console.error('Error fetching user data:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.post('/api/useraccsettingup', async (req, res) => {
    try {
        const accessToken = req.headers['access-token'];
        const datatoupdate = req.body.accdta;

        const [rows] = await pool.query('SELECT * FROM users WHERE user_id = ? AND api_token = ?', [datatoupdate[0].user_id, accessToken]);

        console.log(datatoupdate, rows[0].password);

        if (rows[0].password === datatoupdate[0].password) {
            if (!datatoupdate[0].new_pass) {
                console.log("password is blank");
                await pool.query(
                    `UPDATE users 
                         SET username = ?, email = ?, role = ?, profile_picture = ? 
                         WHERE user_id = ? AND api_token = ?`,
                    [datatoupdate[0].username, datatoupdate[0].email, datatoupdate[0].role, datatoupdate[0].profile_picture, datatoupdate[0].user_id, accessToken]
                );
            } else {
                console.log("password is present");
                await pool.query(
                    `UPDATE users 
                 SET username = ?, email = ?, password = ?, role = ?, profile_picture = ? 
                 WHERE user_id = ? AND api_token = ?`,
                    [datatoupdate[0].username, datatoupdate[0].email, datatoupdate[0].new_pass, datatoupdate[0].role, datatoupdate[0].profile_picture, datatoupdate[0].user_id, accessToken]
                );
            }
            res.status(200).json({ message: 'Internal server error' });
        } else {
            console.log("no updates...");
            res.status(500).json({ message: 'Incorrect Password!' });
        }

    } catch (error) {
        console.error('Error fetching user data:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.get('/api/allusersaccount', async (req, res) => {
    try {
        // Adjusted query to fetch specific user based on username and api_token

        // const nouser = req.query.usr;
        // const [rows] = await pool.query('SELECT * FROM users WHERE user_id != ?', [nouser]);
        const [rows] = await pool.query('SELECT * FROM users');

        console.log("rows", req.query.usr);
        // console.log("rows", req.rawHeaders.usr);

        // rows[0].password = "";
        // rows[0].api_token = "";
        // rows[0].api_secret = "";
        res.status(200).json(rows);
    } catch (error) {
        console.error('Error fetching user data:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.post('/api/userdataupdated', async (req, res) => {
    try {
        const datatoupdate = req.body.accdtaedt;

        // const [rows] = await pool.query('SELECT * FROM users WHERE user_id = ?', [datatoupdate[0]]);
        console.log(datatoupdate);

        if (!datatoupdate[23]) {
            console.log("password is blank");
            await pool.query(
                `UPDATE users 
                     SET name = ?, username = ?, email = ?, profile_picture = ?, role = ?, account_status = ? 
                     WHERE user_id = ?`,
                [datatoupdate[9], datatoupdate[1], datatoupdate[2], datatoupdate[8], datatoupdate[12], datatoupdate[6], datatoupdate[0]]
            );
        } else {
            console.log("password is present");
            await pool.query(
                `UPDATE users 
                     SET name = ?, username = ?, email = ?, profile_picture = ?, role = ?, account_status = ?, password = ? 
                     WHERE user_id = ?`,
                [datatoupdate[9], datatoupdate[1], datatoupdate[2], datatoupdate[8], datatoupdate[12], datatoupdate[6], datatoupdate[23], datatoupdate[0]]
            );
        }

        return res.status(200).json({ message: 'success' });

    } catch (error) {
        console.error('Error fetching user data:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.get('/api/alltemplates', async (req, res) => {
    try {

        const [rows] = await pool.query('SELECT * FROM templates');

        if (rows.length === 0) {
            res.status(404).json({ message: 'Page not found' });
        } else {
            console.log("request sent back");
            // console.log(rows);
            res.json(rows);
        }
    } catch (error) {
        console.error('Error fetching page data:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.post('/api/addnewpage', async (req, res) => {
    try {
        const { newname, selecttemp } = req.body;
        const creator_name = req.headers.user;

        const [the_template] = await pool.query(
            'SELECT * FROM templates WHERE page_name = ?', [selecttemp]
        )

        console.log(the_template[0].content, newname, creator_name);

        const insertResult = await pool.query(
            'INSERT INTO pages (page_name, content, author, url, template_name) VALUES (?, ?, ?, ?, ?)',
            [newname, the_template[0].content, creator_name, '/'+newname, selecttemp]
        );

        const newPageId = insertResult[0].insertId;
        console.log(newPageId);
        const [rows] = await pool.query('SELECT * FROM pages WHERE id = ?', [newPageId]);
        res.json(rows);
    } catch (error) {
        console.error('Error fetching page data:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});
app.post('/api/thepagesdel', async (req, res) => {
    try {
        console.log("deleting page");
        const delid = req.body.thepageid;

        // delete the category from database
        await pool.query(
            'DELETE FROM pages WHERE id = ?',
            [delid]
        );

        // Return success message and the newly added row
        res.status(200).json({
            message: 'success',
        });

    } catch (error) {
        console.error('Error adding category:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});
