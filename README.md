# Project Documentation: Express.js MongoDB Authentication

## Introduction
This project is an authentication system built using Express.js and MongoDB. It provides APIs for user registration, email verification with OTP, user information update, user login with JWT token generation, and retrieval of user information using the JWT token.

## Technologies Used
- Express.js
- MongoDB
- JSON Web Tokens (JWT)
- Nodemailer (for sending OTP)
- Bcrypt.js (for password hashing)
- dotenv (for environment variables)
- JavaScript (implemented)

## API Documentation

### 1. User Registration
- **Endpoint**: http://localhost:5000/register
- **Method**: POST
- **Purpose**: Allows users to register with email and password.
- **Request Body**:![image](https://github.com/naveena52/express-mongodb/assets/106575001/85bd5ac3-392a-470a-ad12-1269a8ed0b37)
- **Response**:![image](https://github.com/naveena52/Employee-Details/assets/106575001/196e1256-75a0-4522-bc79-eb82089b965c)

- **Generated OTP**:

   ![image](https://github.com/naveena52/Employee-Details/assets/106575001/0b3d3733-0780-4ada-9bd4-22308d0ab7fd)

- **Exception Handling**:
  - **Case-1 :- Existing User**: If any User Try to Register with Existing Email then exception is handled with a message “user with this mail already exists Please Login”.
     ![image](https://github.com/naveena52/Employee-Details/assets/106575001/5865d304-c139-499a-b73d-af319bdc1a52)

  - **Case-2 :- Password Validation**: If the user tries to register with an unvalidated password, handle the exception with the message "Password must contain at least one uppercase letter, one lowercase letter, one number, one special character, and be at least 8 characters long".
     ![image](https://github.com/naveena52/Employee-Details/assets/106575001/104a7d19-9ba4-49d6-b587-4e372ab6c9b9)
    
### 2. Email Verification
- **Endpoint**: http://localhost:5000/validateuser
- **Method**: POST
- **Purpose**: Verifies user's email using OTP sent to their email address.
- **Request Body**:
  
   ![image](https://github.com/naveena52/Employee-Details/assets/106575001/96394e5a-1f6e-429d-9850-01e1ca1e7ba8)

- **Response**:
  
    ![image](https://github.com/naveena52/Employee-Details/assets/106575001/acf8f05e-cefb-4b38-bcd3-3e6915f5316a)

- **Exceptions Handled**:
  - **Case-1 :-Invalid OTP**: If the user is given the wrong OTP, handle the exception with the message “Invalid Otp”.
      ![image](https://github.com/naveena52/Employee-Details/assets/106575001/89ee1a80-6625-47c7-9085-8b6f7e4ca526)

  - **Case-2 :- Email already Verified**: If any user tries to use an already verified OTP, handle the exception with the message "Email already verified".
   ![image](https://github.com/naveena52/Employee-Details/assets/106575001/bff1edb5-2bf8-41d2-ae63-ff873138135f)


### 3. User Login
- **Endpoint**: http://localhost:5000/login
- **Method**: POST
- **Purpose**: Allows users to login with email and password.
- **Request Body**:![image](https://github.com/naveena52/Employee-Details/assets/106575001/f847e326-92fc-43c7-b8e8-99eaabf9611a)

- **Response**:![image](https://github.com/naveena52/Employee-Details/assets/106575001/b82dfe27-d771-4395-b8ef-28b5b513534f)

- **Exception Handling**:
  - **Case-1:-Unregistered Email**: If any user tries to login with an unregistered/invalid email, handle the exception with the message “Unregistered Email Please Register”.
   ![image](https://github.com/naveena52/Employee-Details/assets/106575001/51ccefcf-2b69-4e81-83b1-e9ecb8c54831)

  - **Case-2:-Password Validation**: If the user tries to login with the wrong password, handle the exception with the message “invalid password”.
   ![image](https://github.com/naveena52/Employee-Details/assets/106575001/47ca2213-d3bd-4f89-be91-6560a36b68ac)


### 4. Update User Information
- **Endpoint**: http://localhost:5000/update-info
- **Method**: PUT
- **Purpose**: Update the User data when the user logs in using JWT token.
- **Request Body**: with JWT token
 ![image](https://github.com/naveena52/Employee-Details/assets/106575001/0e3a06e0-75a4-4be5-9174-c5b07080daf4)
 ![image](https://github.com/naveena52/Employee-Details/assets/106575001/82df9fb8-0a77-433f-91d4-4c4cb3bfde25)

- **Response**:![image](https://github.com/naveena52/Employee-Details/assets/106575001/57a0e819-98da-4b5a-b053-f5c44e56e678)

- **Exception Handling**:
  - **Case-1:-Jwt Token Expiring**: If the user tries to update the user data with an expired JWT token, handle the exception with the message “Token is expired please login again”.
  ![image](https://github.com/naveena52/Employee-Details/assets/106575001/89da2cad-c927-44d0-8ed4-1eaa87691dec)

  - **Case-2:-Unvalidated User**: If a User is not verified with OTP and tries to login and update the data, handle the exception with the message “User is not validated”.
  ![image](https://github.com/naveena52/Employee-Details/assets/106575001/5dc27485-292b-4aad-9dc0-73f59513993e)


### 5. Get User Information
- **Endpoint**: http://localhost:5000/user
- **Method**: GET
- **Purpose**: Retrieves user information using JWT token.
- **Response Body**: with JWT token
 ![image](https://github.com/naveena52/Employee-Details/assets/106575001/af91bd94-a289-4742-ac50-e4501ff29edc)

- **Response**:
 ![image](https://github.com/naveena52/Employee-Details/assets/106575001/081da794-26ab-439a-b131-98ffad197a1a)


## MongoDB Schema
- **User Schema**:![image](https://github.com/naveena52/Employee-Details/assets/106575001/9396fd01-48b2-413c-8629-b0cf1620d575)

- **Database**: Here can see the data in the database with users like one with validated and another not validated.
 ![image](https://github.com/naveena52/Employee-Details/assets/106575001/bff44bef-75a3-4b49-8910-614bcedaffe4)


## Conclusion
This project provides a basic authentication system with functionalities like user registration, email verification, user information update, user login with JWT token generation, and retrieval of user information using the JWT token.
