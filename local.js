require('dotenv').config();
const app = require('./index.js');
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => console.log(`✅ Server lokal jalan di http://localhost:${PORT}`));
