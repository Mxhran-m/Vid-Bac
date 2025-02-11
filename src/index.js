import connectDB from "./db/index.js";
import 'dotenv/config'
import { app } from "./app.js";

const Port = process.env.PORT || 8000

connectDB()
.then( () => {
    app.listen(Port, () => {
        console.log(`Example app listening on port: ${Port}`)
    })
    app.on("error", (err) => {
        console.log("Error:",err)
    })
})
.catch((err) => {
    console.log("MongoDB connection failed!!!", err)
})