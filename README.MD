# PHRealState - Real State Platform
The **PHRealState - Real Estate Platform** is an online marketplace built using the MERN stack, designed to connect buyers and sellers of real estate properties. It provides a seamless and user-friendly experience for property browsing, listing, and management.

# Purpose
The platform aims to simplify real estate transactions by offering tailored features for three distinct user roles:
-   Users: Browse, wishlist, review, and purchase properties effortlessly.
-   Agents: Add and manage property listings, track sold and requested properties.
-   Admins: Oversee platform operations by managing properties, users, and reviews to ensure a secure and efficient environment.
By combining intuitive features with robust management tools, the platform ensures a streamlined and transparent real estate process for all stakeholders.
# Features

### General Features
- **Responsive Design**: A user-friendly interface optimized for both desktop and mobile devices.
- **Secure Authentication**: User login and registration with role-based access control (User, Agent, Admin).
- **Property Search**: Advanced filters to search properties by location, price range, property type, and more.

### User Features
- **Property Wishlist**: Save favorite properties for easy access later.
- **Property Purchase**: Seamlessly purchase properties with secure payment integration.
- **Reviews and Ratings**: Provide feedback and ratings for properties.
- **Personal Dashboard**: Manage wishlists, purchases, and reviews.

### Agent Features
- **Add Property Listings**: Upload new properties with details, images, and pricing.
- **Track Properties**: View and manage requested and sold properties.
- **Performance Insights**: Access data on sales and customer interactions.

### Admin Features
- **User Management**: Add, remove, or update user accounts and roles.
- **Property Management**: Approve, update, or remove property listings.
- **Review Moderation**: Monitor and manage user reviews and ratings.
- **Platform Analytics**: Gain insights into platform performance and user activity.


# Technology Stack

-   **Frontend**: React (with DaisyUI and Tailwind CSS for styling).
-   **Backend**: NodeJs (for managing data and APIs).
-   **Database**: MongoDB (for storing user queries, recommendations, and comments).
-   **Deployment**: Vite (for a fast development environment and production build).
-   **State Management**: Context API (for managing application state).

### Future Enhancements (Extra Features Idea)
- **Real-Time Chat**: Enable direct communication between users and agents.
- **Push Notifications**: Notify users about new listings and updates.
- **Machine Learning Recommendations**: Provide personalized property recommendations based on user behavior.

# Generate Secret
type node then enter then : `require('crypto').randomBytes(64).toString('hex')`

## Instructions for Running the Project Locally
### Backend (Query-Server)
1.**Install the dependencies:**
-   `npm install`
2. **Set up environment variables:**
-   Create a .env file in the query-server directory.Add your Credentials Here. simillar to .env.example.
3. **Start the backend server:**
-   `npm run start` or install nodemon globally!
4. **Verify the server is running:**
The backend server will be accessible at http://localhost:5000 (http://localhost:port)

# About

-   Admin email: admin@gmail.com
-   Admin password: admin@gmail.comA1
-   Agent email: agent@gmail.com
-   Agent password: agent@gmail.comA1
-   Front-end Live Site Link: phrealstate.web.app