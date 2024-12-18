// Import required modules
const express = require('express');
const bodyParser = require('body-parser');

// Create an Express app
const app = express();

// Use body-parser middleware to parse POST request bodies
app.use(bodyParser.urlencoded({ extended: true }));

// Define the POST route to receive the form data
app.post('/', (req, res) => {
    // Get the credentials from the request body
    const { username, password } = req.body;
    
    // For demonstration, simply log the credentials to the console
    console.log(`Received credentials: Username: ${username}, Password: ${password}`);
    
    // Respond with a success message (you can adjust this based on your need)
    res.send('Login successful!');
});

// Set the port the server will listen to
const port = 3000;
app.listen(port, () => {
    console.log(`Server is running on http://10.0.1.33:${port}`);
});
