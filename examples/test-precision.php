<?php
/**
 * Test cases for precision verification
 * - TRUE POSITIVES: Real vulnerabilities
 * - FALSE POSITIVES: Code that looks like vulnerabilities but isn't
 */

// ============ TRUE POSITIVE: XSS via echo ============
if (isset($_REQUEST['name'])) {
    $name = $_REQUEST['name'];
    echo "Hello " . $name;  // REAL XSS - tainted $name directly output
}

// ============ FALSE POSITIVE CANDIDATE: isset without output ============
if (isset($_REQUEST['id'])) {
    $id = $_REQUEST['id'];
    // No output here - just checking if parameter exists
    $count = count($_REQUEST);
}

// ============ TRUE POSITIVE: SQLi with tainted variable ============
$user_id = $_GET['user_id'];
$query = "SELECT * FROM users WHERE id = '$user_id'";
$result = mysqli_query($connection, $query);

// ============ FALSE POSITIVE CANDIDATE: Assignment but no sink ============
$config = $_REQUEST['config'];
// $config is set but never used - should not trigger vulnerability

// ============ FALSE POSITIVE CANDIDATE: Sanitized output ============
$unsafe_input = $_POST['message'];
$safe_output = htmlspecialchars($unsafe_input, ENT_QUOTES, 'UTF-8');
echo $safe_output;  // Should NOT be vulnerable - input is sanitized

// ============ TRUE POSITIVE: Direct superglobal interpolation ============
$sql = "SELECT * FROM users WHERE username = '{$_GET['user']}'";
$result = mysqli_query($connection, $sql);

// ============ FALSE POSITIVE CANDIDATE: Comparison not output ============
if ($_REQUEST['admin'] == 'true') {
    $admin = true;
}

// ============ TRUE POSITIVE: Command injection ============
$filename = $_GET['file'];
system("cat " . $filename);  // REAL CODE INJECTION

// ============ FALSE POSITIVE CANDIDATE: String concatenation but hardcoded ============
$greeting = "Welcome to " . $_SERVER['HTTP_HOST'];
// This uses $_SERVER which is less critical than user input
