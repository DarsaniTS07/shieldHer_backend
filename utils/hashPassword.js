const bcrypt = require('bcryptjs');

(async () => {
  const password = 'password123'; // Replace with your desired password
  const hashedPassword = await bcrypt.hash(password, 10);
  console.log('Hashed password:', hashedPassword);
})();
