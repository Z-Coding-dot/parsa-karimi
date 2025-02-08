Project Title
Personal Blog
Description
This project is a web application that provides user authentication, an admin panel for user management, and displays data from two APIs. It features a clean and responsive design with a consistent navigation bar and footer across all pages.

File Structure

project/
├── .env # Environment variables (e.g., API keys, MongoDB URI)
├── desktop.ini # Desktop configuration file
├── package.json # Dependencies and project metadata
├── README.md # Documentation with setup instructions and design decisions
├── seed.js # Script to seed initial data into the database
├── server.js # Core server logic and API integration
├── views/
│ ├── admin.ejs # Admin panel for managing users
│ ├── api1.ejs # Page for displaying data from API 1
│ ├── api2.ejs # Page for displaying data from API 2
│ ├── footer.ejs # Footer with your name and group
│ ├── history.ejs # History page showing user interactions
│ ├── login.ejs # Login page
│ ├── main.ejs # Main page after login
│ ├── navbar.ejs # Navigation bar included in all pages
│ └── signup.ejs # Signup page

Setup Instructions
Clone the repository to your local machine.
Navigate to the project directory.
Create a .env file and add your environment variables, including API keys and MongoDB URI.
npm install

Start the server with:
node server.js

Open your browser and go to http://localhost:3000 to access the application.

Admin Credentials

Username: parsa
Password: 232134

Design Decisions
The application uses EJS as the templating engine for rendering HTML pages.
Express.js is utilized for handling server requests and routing.
The project is structured to separate views, configuration, and server logic for better maintainability.
Acknowledgments
Thank you to all contributors and resources that helped in the development of this project.
