# Product Hunt API

Welcome to the backend API of our P4U Website. This API provides endpoints to manage user authentication, product submissions, moderation, and administrative tasks.

### Base URL
The base URL for all API endpoints is `http://localhost:3000`.

### Setup Instructions
1. Clone the repository
2. Navigate into the project directory
3. Install dependencies
4. Create a `.env` file in the root directory and add the following environment variables
5. Start the server:

### Live API URL
[P4U](https://my-project-server.onrender.com/)

### API Endpoints

#### Authentication
- **POST /api/auth/register:** Register a new user.
- **POST /api/auth/login:** Login a user.
- **POST /api/auth/logout:** Logout a user.
- **POST /api/auth/google-login:** Login via Google.

#### Products
- **GET /api/products:** Fetch all products.
- **POST /api/products/submit:** Submit a new product.
- **GET /api/products/:id:** Fetch product details.
- **POST /api/products/:id/upvote:** Upvote a product.
- **POST /api/products/:id/report:** Report a product.

#### Reviews
- **POST /api/reviews/:id:** Post a review for a product.

#### Users
- **GET /api/users:** Fetch all users.
- **PATCH /api/users/:id/make-moderator:** Make a user a moderator.
- **PATCH /api/users/:id/make-admin:** Make a user an admin.

### Technologies Used
- Node.js
- Express.js
- MongoDB
- Mongoose
- JSON Web Tokens (JWT)
- bcrypt

### Dependencies Used
- **cors:** ^2.8.5
- **dotenv:** ^16.4.5
- **express:** ^4.19.2
- **jsonwebtoken:** ^9.0.2
- **mongodb:** ^6.7.0
- **nodemon:** ^3.1.2
- **stripe:** ^15.10.0
### Credits
- This API was developed by MD Rakibul Islam



