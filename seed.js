const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const { User } = require("./server.js"); // Correct import

// Connect to MongoDB Atlas
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

async function seedUsers() {
  try {
    // Hash passwords
    const adminPassword = await bcrypt.hash("admin123", 10);
    const userPassword = await bcrypt.hash("user123", 10);

    // Create an admin user
    await User.create({
      username: "admin",
      password: adminPassword,
      isAdmin: true,
    });

    // Create a regular user
    await User.create({
      username: "user",
      password: userPassword,
      isAdmin: false,
    });

    console.log("Users seeded successfully");
    process.exit(0);
  } catch (error) {
    console.error("Error seeding users:", error);
    process.exit(1);
  }
}

seedUsers();