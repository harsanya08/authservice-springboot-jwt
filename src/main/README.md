# Auth Service – Spring Boot & JWT

A backend authentication service built using Spring Boot, Spring Security, and JWT.

## Features
- User registration with BCrypt password hashing
- User login with JWT token generation
- Stateless authentication using JSON Web Tokens
- Layered architecture (Controller, Service, Repository)
- H2 in-memory database with JPA
- RESTful APIs tested via HTTP clients

## Tech Stack
- Java 17
- Spring Boot
- Spring Security
- JWT (jjwt)
- JPA / Hibernate
- H2 Database
- Maven

## API Endpoints

### Register
`POST /auth/register`

```json
{
  "email": "user@example.com",
  "password": "password123"
}
