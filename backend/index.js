const express = require('express');
const bcrypt = require('bcrypt');
const app = express();
const port = 3000;
const cors = require('cors');
var crypto = require('crypto');

// Middleware to parse request body
app.use(express.json());
// Enable All CORS Requests
app.use(cors());

// Encryption
const algorithm = 'aes-256-cbc';
const key = Buffer.from([0xc8, 0x3d, 0xbf, 0x37, 0xd6, 0x24, 0xd0, 0xae, 0xf9, 0xe7, 0xd7, 0xae, 0x9e, 0x9a, 0xde, 0x63, 0x4f, 0xc8, 0x1c, 0xa8, 0xc5, 0x9c, 0x1e, 0xb8, 0xa2, 0x29, 0xa7, 0x94, 0x85, 0xcf, 0x36, 0xd8])
const iv = Buffer.from([0x85, 0x2b, 0x01, 0x2c, 0x8d, 0x3e, 0x8d, 0xff, 0xe3, 0x9c, 0xde, 0x10, 0x9e, 0xd1, 0xab, 0xb8]);
// console.log(encrypt("plaintext"));

function encrypt(text){
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
}

function decrypt(text){
    const decipher = crypto.createDecipheriv(algorithm, key, iv);
    let decrypted = decipher.update(text, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted; //myPlainText
}


// Route to handle password hashing
app.post('/sendFromScrt', async (req, res) => {
    try {
      const { hidden_text } = req.body;
      const encrpytedText = encrypt(hidden_text);
      res.json({ encrpytedText });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Internal server error' });
    }
});
  
  // Route to handle password hashing
  app.post('/sendFromEvm', async (req, res) => {
      try {
        const { temp_token_uri } = req.body;
        const decryptedText = decrypt(temp_token_uri);
        res.json({ decryptedText });
      } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
      }
    });

// // Route to handle password hashing
// app.post('/sendFromScrt', async (req, res) => {
//   try {
//     const { hidden_text } = req.body;

//     // Generate a salt
//     const saltRounds = 10;
//     const salt = await bcrypt.genSalt(saltRounds);

//     // Hash the password
//     const hashedPassword = await bcrypt.hash(hidden_text, salt);
//     console.log(hashedPassword);    
//     res.json({ hashedPassword });


//   } catch (err) {
//     console.error(err);
//     res.status(500).json({ error: 'Internal server error' });
//   }
// });

// // Route to handle password hashing
// app.post('/sendFromEvm', async (req, res) => {
//     try {
//       const { temp_token_uri } = req.body;
  
//       // Generate a salt
//       const saltRounds = 10;
//       const salt = await bcrypt.genSalt(saltRounds);
  
//       // Hash the password
//       const hashedPassword = await bcrypt.hash(hidden_text, salt);
//       console.log(hashedPassword);    
//       res.json({ hashedPassword });
  
  
//     } catch (err) {
//       console.error(err);
//       res.status(500).json({ error: 'Internal server error' });
//     }
//   });

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});