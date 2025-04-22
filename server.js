const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const azure = require('azure-storage');
const multer = require('multer');  // Middleware for handling file uploads
const cors = require('cors'); // To handle cross-origin requests
const app = express();

app.use(cors());
app.use(express.json()); // Middleware to parse JSON request bodies

const SECRET_KEY = 'your_secret_key'; // Use a stronger secret in production

// Mock in-memory users (Replace with a real database later)
let users = [
  { username: 'creatorUser', passwordHash: bcrypt.hashSync('creatorPassword', 8), role: 'creator' },
  { username: 'consumerUser', passwordHash: bcrypt.hashSync('consumerPassword', 8), role: 'consumer' }
];

// Azure Blob Storage setup
const blobService = azure.createBlobService(
  'DefaultEndpointsProtocol=https;AccountName=mediaappdemo;AccountKey=PItowfMJnUZKfCPJl4lV6NnVvjfGAls4rAX8VdSCLI9hdmsu5VMqyaRue3TN4ft9YYD5qq7j4pEC+AStgmNJ1w==;EndpointSuffix=core.windows.net'
);

// Multer setup for handling video uploads (storing videos in memory temporarily)
const storage = multer.memoryStorage();  // Storing video in memory
const upload = multer({ storage: storage });  // Use multer for handling video uploads

// Function to upload videos to Azure Blob Storage
function uploadVideoToAzure(blobName, fileBuffer) {
  return new Promise((resolve, reject) => {
    blobService.createBlockBlobFromText('videos', blobName, fileBuffer, function (err, result) {
      if (err) {
        reject('Error uploading video: ' + err);
      } else {
        resolve('Video uploaded successfully!');
      }
    });
  });
}

// Login Route - User login (returns JWT token)
app.post('/login', (req, res) => {
    const { username, password, role } = req.body;  // Include role from the login form
    const user = users.find(u => u.username === username);

    if (!user) {
        return res.status(401).send('User not found');
    }

    if (bcrypt.compareSync(password, user.passwordHash)) {
        // If role from frontend doesn't match stored role, return error
        if (role !== user.role) {
            return res.status(403).send('Role mismatch');
        }

        const token = jwt.sign({ username: user.username, role: user.role }, SECRET_KEY, { expiresIn: '1h' });
        res.json({ token, role: user.role });
    } else {
        res.status(401).send('Invalid password');
    }
});


// Signup Route - Register new users (temporary mock in-memory storage)
app.post('/signup', (req, res) => {
  const { username, password, role } = req.body;
  const passwordHash = bcrypt.hashSync(password, 8);

  // Check if user already exists
  const userExists = users.find(u => u.username === username);
  if (userExists) {
    return res.status(400).send('User already exists');
  }

  // Add new user to the in-memory "database"
  users.push({ username, passwordHash, role });
  res.status(201).send('User created successfully');
});

// Middleware to protect routes based on user role
const protectRoute = (role) => {
  return (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1]; // Get token from Authorization header
    if (!token) return res.status(401).send('Unauthorized');

    try {
      const decoded = jwt.verify(token, SECRET_KEY);
      if (role && decoded.role !== role) {
        return res.status(403).send('Forbidden');
      }
      req.user = decoded; // Store decoded user info
      next();
    } catch (error) {
      res.status(401).send('Unauthorized');
    }
  };
};

// Route for creators to upload videos (protected route)
app.post('/upload', protectRoute('creator'), upload.single('video'), (req, res) => {
  const videoFile = req.file; // Get the uploaded video file

  if (!videoFile) {
    return res.status(400).send('No video file uploaded');
  }

  // Upload the video to Azure Blob Storage
  const blobName = videoFile.originalname; // The name of the video in Blob Storage
  uploadVideoToAzure(blobName, videoFile.buffer)
    .then(message => res.send(message)) // Send success message
    .catch(error => res.status(500).send(error)); // Handle any error during upload
});

// Route for consumers to view videos (protected route)
app.get('/view', protectRoute('consumer'), (req, res) => {
  // Example video filenames (you should update with actual video files in your Blob Storage)
  const videos = [
    { id: 1, title: "Skateboarding Fun", description: "Watch these skateboarders perform awesome tricks!", url: blobService.getUrl('videos', '4824358-uhd_3840_2160_30fps.mp4') },
    { id: 2, title: "Curious Cat Playtime", description: "A cute cat exploring and playing around.", url: blobService.getUrl('videos', '6853904-uhd_2160_4096_25fps.mp4') },
    { id: 3, title: "Playful Kitten Adventures", description: "A kitten chasing after a toy, full of energy!", url: blobService.getUrl('videos', '855029-hd_1920_1080_30fps.mp4') },
    { id: 4, title: "Funny Cats Having Fun", description: "Enjoy watching these playful cats in action!", url: blobService.getUrl('videos', 'uhd_25fps.mp4') }
];


  // Randomize the order of videos
  const randomizedVideos = videos.sort(() => Math.random() - 0.5);

  // Send 3 random videos
  res.status(200).json(randomizedVideos.slice(0, 3));  // Sending 3 random videos
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
