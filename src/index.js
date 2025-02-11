import connectDB from "./db/index.js";
import 'dotenv/config'

connectDB()
console.log(`Example app running on port: ${process.env.PORT}`);
