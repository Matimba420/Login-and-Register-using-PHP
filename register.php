<?php
session_start();
// Change this to your connection info.
$DATABASE_HOST = 'localhost';
$DATABASE_USER = 'root';
$DATABASE_PASS = '';
$DATABASE_NAME = 'phplogin';

// Create connection
$con = mysqli_connect($DATABASE_HOST, $DATABASE_USER, $DATABASE_PASS, $DATABASE_NAME);

// Check connection
if (mysqli_connect_errno()) {
    exit('Failed to connect to MySQL: ' . mysqli_connect_error());
}

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $username = $_POST['username'];
    $email = $_POST['email'];
    $password = $_POST['password'];

    // Form validation
    if (!empty($username) && !empty($email) && !empty($password)) {
        // Hash the password
        $hashed_password = password_hash($password, PASSWORD_DEFAULT);

        // Prepare and bind
        $stmt = $con->prepare("INSERT INTO accounts (username, email, password) VALUES (?, ?, ?)");
        if ($stmt === false) {
            exit('Prepare failed: ' . htmlspecialchars($con->error));
        }
        $stmt->bind_param("sss", $username, $email, $hashed_password);

        // Execute the statement
        if ($stmt->execute()) {
            // Registration successful, log the user in
            $stmt->close();

            // Prepare the login statement
            $stmt = $con->prepare('SELECT id FROM accounts WHERE username = ?');
            if ($stmt === false) {
                exit('Prepare failed: ' . htmlspecialchars($con->error));
            }
            $stmt->bind_param('s', $username);
            $stmt->execute();
            $stmt->store_result();

            if ($stmt->num_rows > 0) {
                $stmt->bind_result($id);
                $stmt->fetch();

                // Create sessions
                session_regenerate_id();
                $_SESSION['loggedin'] = TRUE;
                $_SESSION['name'] = $username;
                $_SESSION['id'] = $id;
                header('Location: index.html');
            } else {
                echo 'No account found for the provided username.';
            }

            $stmt->close();
        } else {
            echo "Execute failed: " . htmlspecialchars($stmt->error);
        }
    } else {
        echo "All fields are required!";
    }
}

$con->close();
?>
