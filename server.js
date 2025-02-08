const express = require("express");
const mongoose = require("mongoose");
const dotenv = require("dotenv");
const session = require("express-session");
const bodyParser = require("body-parser");
const path = require("path");
const axios = require("axios");
const bcrypt = require("bcrypt");
const flash = require("connect-flash");
const i18n = require("i18n");
const cookieParser = require("cookie-parser");
const translate = require("google-translate-api-x");


dotenv.config();
const app = express();
const PORT = 3000;

// Middleware Setup
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static("public"));
app.use(flash());
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// Session Setup
app.use(
  session({
    secret: "your_secret_key",
    resave: false,
    saveUninitialized: true,
  })
);
app.use(cookieParser());

// i18n Configuration
i18n.configure({
  locales: ["en", "fa", "ru"],
  directory: path.join(__dirname, "locales"),
  defaultLocale: "en",
  cookie: "lang",
  queryParameter: "lang",
  autoReload: true,
  syncFiles: true,
});
app.use(i18n.init);

// Create a custom HTTPS agent to ignore SSL certificate errors
// const httpsAgent = new https.Agent({
//   rejectUnauthorized: false,
// });
// axios.defaults.httpsAgent = httpsAgent;

// Language Middleware
app.use((req, res, next) => {
  let lang = req.query.lang || req.cookies.lang || "en";
  res.cookie("lang", lang, { maxAge: 900000, httpOnly: true });
  res.setLocale(lang);
  next();
});

app.use((req, res, next) => {
  res.locals.user = req.session.user || null; // Pass user to all views
  res.locals.successMessage = req.flash("success");
  res.locals.errorMessage = req.flash("error");
  next();
});

// MongoDB connection
mongoose
  .connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("Connected to MongoDB Atlas"))
  .catch((error) => console.error("MongoDB connection error:", error));

// Schemas and Models
// Define Schemas
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  isAdmin: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now },
});

// Define Item Schema
const itemSchema = new mongoose.Schema({
  pictures: [{ type: String, required: true }],
  name_en: { type: String, required: true },
  name_local: { type: String, required: true },
  description_en: { type: String, required: true },
  description_local: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  updatedAt: Date,
  deletedAt: Date,
});

const Item = mongoose.model("Item", itemSchema);

const api1Schema = new mongoose.Schema({
  title: String,
  description: String,
  url: String,
  publishedAt: Date,
  source: String,
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  createdAt: { type: Date, default: Date.now },
});

const jokeSchema = new mongoose.Schema({
  setup: { type: String, required: true },
  delivery: { type: String },
  category: { type: String },
  type: { type: String },
  createdAt: { type: Date, default: Date.now },
});

module.exports = mongoose.model("Joke", jokeSchema);

const historySchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  action: { type: String, required: true },
  input: { type: String },
  date: { type: Date, default: Date.now },
});

const User = mongoose.model("User", userSchema);
const API1 = mongoose.model("API1", api1Schema);
const Joke = mongoose.model("Joke", jokeSchema);
const History = mongoose.model("History", historySchema);

// Middleware to check session
function isAuthenticated(req, res, next) {
  if (!req.session.user) {
    return res.redirect("/"); // Redirect to login if not authenticated
  }
  next();
}

app.get("/change-language", (req, res) => {
  res.cookie("lang", req.query.lang, { maxAge: 900000, httpOnly: true });

  // Secure redirect handling
  const redirectUrl = req.get("Referrer") || "/";
  res.redirect(redirectUrl);
});

// Routes
app.get("/", (req, res) => res.render("login"));

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  console.log(`Login attempt for username: ${username}`);
  const user = await User.findOne({ username });
  if (user && (await bcrypt.compare(password, user.password))) {
    req.session.user = user;
    return res.redirect("/main");
  }
  req.flash("error", "Wrong username or password, please try again.");
  res.redirect("/");
});

app.get("/signup", (req, res) => {
  res.render("signup");
});

app.post("/signup", async (req, res) => {
  const { username, password } = req.body;

  try {
    // Check if the username already exists
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      req.flash("error", "Username already exists. Please choose another.");
      return res.redirect("/signup");
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create a new user
    const newUser = new User({
      username,
      password: hashedPassword,
    });

    // Save the user to MongoDB
    await newUser.save();

    // Add success message and redirect to login
    req.flash("success", "Account created successfully. Please log in.");
    res.redirect("/");
  } catch (error) {
    console.error("Error during sign-up:", error);
    req.flash("error", "An error occurred. Please try again.");
    res.redirect("/signup");
  }
});

app.get("/main", isAuthenticated, (req, res) => {
  res.render("main", {
    username: req.session.user.username,
    isAdmin: req.session.user.isAdmin, // Pass isAdmin to EJS
  });
});

app.get("/history", isAuthenticated, async (req, res) => {
  try {
    const history = await History.find({ userId: req.session.user._id })
      .sort({ date: -1 })
      .limit(10); // Show last 10 searches

    const jokeHistory = await History.find({ 
      userId: req.session.user._id, 
      action: "searched_joke" 
    })
    .sort({ date: -1 })
    .limit(10); // Show last 10 joke searches

    res.render("history", {
      username: req.session.user.username,
      history,
      jokeHistory, // Pass joke history to history.ejs
    });
  } catch (error) {
    console.error("Error fetching history:", error);
    res.status(500).send("Internal Server Error");
  }
});


app.get("/admin", isAuthenticated, async (req, res) => {
  if (!req.session.user || !req.session.user.isAdmin) {
    return res.status(403).send("Access denied");
  }
  try {
    const users = await User.find();
    res.render("admin", { users });
  } catch (error) {
    console.error("Error fetching users:", error);
    res.status(500).send("Internal Server Error");
  }
});

app.post("/admin/add", isAuthenticated, async (req, res) => {
  console.log(req.body); // Log the request body to debug issues

  const { username, password, isAdmin } = req.body;

  if (!username || !password) {
    req.flash("error", "Username and password are required");
    return res.redirect("/admin");
  }

  try {
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      req.flash("error", "Username already exists. Please choose another.");
      return res.redirect("/admin");
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({
      username,
      password: hashedPassword,
      isAdmin: isAdmin === "true",
    });

    await newUser.save();

    req.flash("success", "User added successfully");
    res.redirect("/admin");
  } catch (error) {
    console.error("Error adding user:", error);
    req.flash("error", "An error occurred while adding the user.");
    res.redirect("/admin");
  }
});

app.post("/admin/edit/:id", async (req, res) => {
  const { id } = req.params;
  const { username, isAdmin } = req.body;
  try {
    await User.findByIdAndUpdate(id, {
      username,
      isAdmin: isAdmin === "true",
    });
    res.sendStatus(200);
  } catch (error) {
    console.error("Error updating user:", error);
    res.status(500).send("Internal Server Error");
  }
});

app.post("/admin/delete/:id", async (req, res) => {
  try {
    await User.findByIdAndDelete(req.params.id);
    res.redirect("/admin");
  } catch (error) {
    console.error("Error deleting user:", error);
    res.status(500).send("Internal Server Error");
  }
});

///////////////////// Search News //////////////////////😎😎😎😎

app.get("/search-news", isAuthenticated, async (req, res) => {
  const userQuery = req.query.query || "default";
  const targetLanguage = req.getLocale();
  let translatedQuery = userQuery;

  try {
    // Translate query to English if it's not already English
    if (targetLanguage !== "en") {
      const translatedText = await translate(userQuery, { to: "en" });
      translatedQuery = translatedText.text;
    }

    // Fetch news articles
    const response = await axios.get(
      `https://newsapi.org/v2/everything?q=${encodeURIComponent(
        translatedQuery
      )}&apiKey=${process.env.NEWS_API_KEY}`
    );

    let articles = response.data.articles || [];
    if (!articles.length) throw new Error("No results from NewsAPI");

    // Translate articles into user's language
    articles = await Promise.all(
      articles.map(async (article) => {
        const titleText = article.title || "No title available";
        let descText = article.description || "No description available";

        // Ensure valid description (prevent empty strings)
        if (!descText.trim()) {
          descText = "No description available";
        }

        const titleTrans = await translate(titleText, { to: targetLanguage });
        const descTrans = await translate(descText, { to: targetLanguage });

        return {
          title: titleTrans.text,
          description: descTrans.text.trim() || "No description available",
          url: article.url,
          urlToImage: article.urlToImage || "/default-image.jpg",
          source: article.source?.name || "Unknown Source",
          publishedAt: article.publishedAt,
        };
      })
    );

    // ✅ Save user search in history, including results
    await History.create({
      userId: req.session.user._id,
      action: "Searched for news",
      input: userQuery,
      date: new Date(),
      results: articles.slice(0, 3), // ✅ Save only top 3 results to avoid excessive storage
    });

    res.render("api1", { articles, currentLocale: targetLanguage });
  } catch (error) {
    console.error("Error fetching news:", error.message);
    res.render("api1", { articles: [], currentLocale: targetLanguage });
  }
});

// Fetching Top Headlines
app.get("/api1", isAuthenticated, async (req, res) => {
  const query = "default"; 
  try {
    const response = await axios.get(
      `https://newsapi.org/v2/top-headlines?country=us&apiKey=${process.env.NEWS_API_KEY}`,
      {
        headers: {
          "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        },
      }
    );

    const userId = req.session.user._id;

    for (const article of response.data.articles) {
      await API1.create({
        title: article.title,
        description: article.description || "No description available",
        url: article.url,
        publishedAt: article.publishedAt,
        source: article.source.name,
        userId,
      });
    }

    await History.create({
      userId,
      action: "Fetched top headlines from API1",
    });

    res.render("api1", {
      articles: response.data.articles,
      currentLocale: req.getLocale(),
    });
  } catch (error) {
    console.error("Primary API failed. Trying fallback API...", error.message);
    try {
      const fallbackResponse = await axios.get(
        `https://newsdata.io/api/1/news?apikey=${process.env.SECOND_NEWS_API_KEY}&q=${query}`
      );

      const userId = req.session.user._id;

      for (const article of fallbackResponse.data.results) {
        await API1.create({
          title: article.title,
          description: article.description || "No description available",
          url: article.link,
          publishedAt: article.pubDate,
          source: article.source_id,
          userId,
        });
      }

      await History.create({
        userId,
        action: "Fetched top headlines from fallback API",
      });

      res.render("api1", { articles: fallbackResponse.data.results });
    } catch (fallbackError) {
      console.error("Both APIs failed:", fallbackError.message);
      res.status(500).send("Error fetching news articles");
    }
  }
});
 



// Route to render joke search page
app.get("/api2", isAuthenticated, async (req, res) => {
  try {
    // Fetch user's joke search history
    const history = await History.find({ userId: req.session.user._id })
      .sort({ date: -1 })
      .limit(5); // Show last 5 searches

    // Fetch recent jokes from MongoDB
    const jokes = await Joke.find().sort({ createdAt: -1 }).limit(5);

    res.render("api2", { jokes, history, currentLocale: req.getLocale() });
  } catch (error) {
    console.error("Error fetching history:", error);
    res.render("api2", {
      jokes: [],
      history: [],
      currentLocale: req.getLocale(),
    });
  }
});

// Home Route
app.get("/", (req, res) => {
  res.render("api2", { jokes: [], history: [] });
});

// Search Jokes Route
app.get("/search-jokes", isAuthenticated, async (req, res) => {
  let userQuery = req.query.query || "funny"; // Default keyword
  const targetLanguage = req.query.language_code || "en"; // Default to English

  try {
    console.log(`User search query: ${userQuery} (Target Language: ${targetLanguage})`);

    // Step 1: Translate the query to English if it's not already in English
    if (targetLanguage !== "en") {
      const translatedQuery = await translate(userQuery, { to: "en" });
      userQuery = translatedQuery.text;
      console.log(`Translated query to English: ${userQuery}`);
    }

    // Step 2: Fetch jokes using the translated query
    const response = await axios.get(
      `https://api.chucknorris.io/jokes/search?query=${encodeURIComponent(userQuery)}`
    );

    console.log("API Response:", response.data);

    let jokes = response.data.result || [];
    if (!jokes.length) throw new Error("No jokes found.");

    // Step 3: Translate jokes back to the selected language (if needed)
    jokes = await Promise.all(
      jokes.map(async (joke) => {
        if (targetLanguage !== "en") {
          try {
            const translatedJoke = await translate(joke.value, { to: targetLanguage });
            return { joke: translatedJoke.text, category: "Chuck Norris" };
          } catch (err) {
            console.error("Translation error:", err.message);
            return { joke: joke.value, category: "Chuck Norris" };
          }
        } else {
          return { joke: joke.value, category: "Chuck Norris" };
        }
      })
    );

    // Step 4: Save to MongoDB (avoid duplicates)
    for (let joke of jokes.slice(0, 5)) {
      const existingJoke = await Joke.findOne({ setup: joke.joke });
      if (!existingJoke) {
        await Joke.create({
          setup: joke.joke,
          delivery: null,
          category: joke.category || "General",
          type: "single",
        });
      }
    }

    // Step 5: Save search history
    const newSearch = new History({
      userId: req.session.user._id,
      input: req.query.query, // Save original input
      language: targetLanguage,
      action: "searched_joke",
      date: new Date(),
    });
    await newSearch.save();

    // Step 6: Fetch updated history
    const history = await History.find({ userId: req.session.user._id })
      .sort({ date: -1 })
      .limit(5);

    // Step 7: Render results
    res.render("api2", { jokes, history, user: req.session.user });
  } catch (error) {
    console.error("Error fetching jokes:", error.message);
    res.render("api2", { jokes: [], history: [], error: "Error fetching jokes", user: req.session.user });
  }
});


app.use(express.static(path.join(__dirname, "public")));

// Add Item (Admin Only)
app.post("/admin/item/add", isAuthenticated, async (req, res) => {
  if (!req.session.user.isAdmin) return res.status(403).send("Access denied");

  const { pictures, name_en, name_local, description_en, description_local } = req.body;

  try {
    // Validate and ensure pictures is an array of valid URLs
    const validatedPictures = Array.isArray(pictures)
      ? pictures.filter(isValidURL)
      : pictures.split(",").map((pic) => pic.trim()).filter(isValidURL);

    const newItem = new Item({
      pictures: validatedPictures,
      name_en,
      name_local,
      description_en,
      description_local,
    });
    await newItem.save();
    req.flash("success", "Item added successfully");
    res.redirect("/admin");
  } catch (error) {
    console.error("Error adding item:", error);
    req.flash("error", "Failed to add item");
    res.redirect("/admin");
  }
});

// Edit Item (Admin Only)
app.put("/admin/item/edit/:id", isAuthenticated, async (req, res) => {
  if (!req.session.user.isAdmin) return res.status(403).send("Access denied");

  const { name_en, name_local, description_en, description_local, pictures } = req.body;

  try {
    // Validate and ensure pictures is an array of valid URLs
    const validatedPictures = Array.isArray(pictures)
      ? pictures.filter(isValidURL)
      : pictures.split(",").map((pic) => pic.trim()).filter(isValidURL);

    await Item.findByIdAndUpdate(req.params.id, {
      $set: {
        name_en,
        name_local,
        description_en,
        description_local,
        pictures: validatedPictures,
        updatedAt: new Date(),
      },
    });

    res.sendStatus(200);
  } catch (error) {
    console.error("Error updating item:", error);
    res.status(500).send("Internal Server Error");
  }
});

// Soft Delete Item (Admin Only)
app.delete("/admin/item/delete/:id", isAuthenticated, async (req, res) => {
  if (!req.session.user.isAdmin) return res.status(403).send("Access denied");

  try {
    await Item.findByIdAndUpdate(req.params.id, { deletedAt: new Date() });
    res.sendStatus(200);
  } catch (error) {
    console.error("Error deleting item:", error);
    res.status(500).send("Internal Server Error");
  }
});

// Fetch All Active Items
app.get("/items", async (req, res) => {
  try {
    const items = await Item.find({ deletedAt: null });
    res.json(items);
  } catch (error) {
    console.error("Error fetching items:", error);
    res.status(500).send("Internal Server Error");
  }
});

// Fetch Single Item by ID
app.get("/items/:id", async (req, res) => {
  try {
    const item = await Item.findById(req.params.id);
    if (!item || item.deletedAt) {
      return res.status(404).send("Item not found");
    }
    res.json(item);
  } catch (error) {
    console.error("Error fetching item:", error);
    res.status(500).send("Internal Server Error");
  }
});

// Utility to validate URLs
function isValidURL(url) {
  try {
    new URL(url);
    return true;
  } catch (_) {
    return false;
  }
}


app.listen(PORT, () =>
  console.log(`Server is running on http://localhost:${PORT}`)
);

module.exports = { User };