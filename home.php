<?php
require 'db.php';

if (!isset($_SESSION['user_id'])) {
    header("Location: index.php");
    exit;
}

$max_idle_seconds = 900;
if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity'] > $max_idle_seconds)) {
    log_system_event($conn, $_SESSION['username'], 'SESSION_TIMEOUT_EXPIRED');
    session_unset();
    session_destroy();
    header("Location: index.php?expired=1");
    exit;
}
$_SESSION['last_activity'] = time();

// Secret key used for database AES encryption
$encryption_key = 'YourSuperSecretEncryptionKeyGoesHere';
$message = "";
$status = "";

// Handle adding a new credential
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['action']) && $_POST['action'] === 'add_credential') {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die("Security token validation failed.");
    }

    $site_name = trim($_POST['site_name']);
    $site_username = trim($_POST['site_username']);
    $site_password = trim($_POST['site_password']);

    if (!empty($site_name) && !empty($site_username) && !empty($site_password)) {
        // Encrypt the password using MySQL's AES_ENCRYPT
        $stmt = $conn->prepare("INSERT INTO credentials (user_id, site_name, site_username, site_password) VALUES (?, ?, ?, AES_ENCRYPT(?, ?))");
        $stmt->bind_param("issss", $_SESSION['user_id'], $site_name, $site_username, $site_password, $encryption_key);
        
        if ($stmt->execute()) {
            log_system_event($conn, $_SESSION['username'], 'CREDENTIAL_ADDED_' . strtoupper($site_name));
            $message = "Credential saved securely.";
            $status = "success";
        } else {
            $message = "Failed to save data securely.";
            $status = "error";
        }
        $stmt->close();
    }
}

// ==========================================
// HANDLE DELETING A CREDENTIAL (NEW CODE)
// ==========================================
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['action']) && $_POST['action'] === 'delete_credential') {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die("Security token validation failed.");
    }

    $credential_id = intval($_POST['credential_id']);

    // Ensure the entry actually belongs to the logged-in user before deleting
    $stmt = $conn->prepare("DELETE FROM credentials WHERE id = ? AND user_id = ?");
    $stmt->bind_param("ii", $credential_id, $_SESSION['user_id']);
    
    if ($stmt->execute()) {
        log_system_event($conn, $_SESSION['username'], 'CREDENTIAL_DELETED_ID_' . $credential_id);
        $message = "Credential removed successfully.";
        $status = "success";
    } else {
        $message = "Failed to delete the credential.";
        $status = "error";
    }
    $stmt->close();
}

// Fetch all existing credentials for this user, decrypting on the fly
$search_query = "";
if (isset($_GET['search'])) {
    $search_query = trim($_GET['search']);
}

if (!empty($search_query)) {
    $stmt = $conn->prepare("SELECT id, site_name, site_username, AES_DECRYPT(site_password, ?) AS decrypted_password FROM credentials WHERE user_id = ? AND (site_name LIKE ? OR site_username LIKE ?)");
    $search_param = "%" . $search_query . "%";
    $stmt->bind_param("sisss", $encryption_key, $_SESSION['user_id'], $search_param, $search_param);
} else {
    $stmt = $conn->prepare("SELECT id, site_name, site_username, AES_DECRYPT(site_password, ?) AS decrypted_password FROM credentials WHERE user_id = ?");
    $stmt->bind_param("si", $encryption_key, $_SESSION['user_id']);
}

$stmt->execute();
$result = $stmt->get_result();
$credentials = $result->fetch_all(MYSQLI_ASSOC);
$stmt->close();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>DaboreyPass - Dashboard</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; background-color: #0f172a; color: #f8fafc; margin: 0; padding: 20px; }
        .container { max-width: 950px; margin: 0 auto; } /* Widened slightly to account for the new column */
        .header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #334155; padding-bottom: 20px; margin-bottom: 30px; }
        h1 { color: #38bdf8; margin: 0; font-size: 28px; }
        .welcome { color: #94a3b8; font-size: 14px; }
        .logout-btn { padding: 8px 16px; background: #ef4444; color: white; text-decoration: none; border-radius: 4px; font-weight: bold; font-size: 14px; }
        
        .grid { display: grid; grid-template-columns: 1fr 2fr; gap: 30px; }
        .box { background: #1e293b; padding: 25px; border-radius: 8px; border: 1px solid #334155; height: fit-content; }
        h3 { margin-top: 0; color: #38bdf8; border-bottom: 1px solid #334155; padding-bottom: 10px; }
        
        input { width: 100%; padding: 10px; margin: 8px 0 16px 0; box-sizing: border-box; border: 1px solid #475569; border-radius: 4px; background: #0f172a; color: #fff; }
        button { width: 100%; padding: 12px; background: #0284c7; border: none; color: white; border-radius: 4px; cursor: pointer; font-weight: bold; }
        button:hover { background: #0369a1; }

        .search-box { margin-bottom: 20px; display: flex; gap: 10px; }
        .search-box input { margin: 0; }
        .search-box button { width: auto; padding: 0 20px; }

        .error { color: #f87171; background: rgba(248,113,113,0.1); border: 1px solid rgba(248,113,113,0.2); padding: 10px; font-size: 14px; border-radius: 4px; margin-bottom: 15px; }
        .success { color: #34d399; background: rgba(52,211,153,0.1); border: 1px solid rgba(52,211,153,0.2); padding: 10px; font-size: 14px; border-radius: 4px; margin-bottom: 15px; }
        
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #334155; }
        th { background-color: #0f172a; color: #38bdf8; }
        tr:hover { background-color: rgba(56, 189, 248, 0.02); }
        
        .pass-container { display: flex; align-items: center; gap: 6px; }
        .pass-text { font-family: monospace; margin-right: 4px; }
        .toggle-btn, .copy-btn, .delete-btn { color: #fff; border: none; padding: 4px 8px; border-radius: 4px; cursor: pointer; font-size: 11px; width: auto; font-weight: normal; }
        .toggle-btn { background: #475569; }
        .toggle-btn:hover { background: #64748b; }
        .copy-btn { background: #10b981; }
        .copy-btn:hover { background: #059669; }
        
        /* Delete Button styling */
        .delete-btn { background: #b91c1c; }
        .delete-btn:hover { background: #991b1b; }
        .delete-form { display: inline; margin: 0; padding: 0; }

        .no-data { text-align: center; color: #64748b; padding: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1>DaboreyPass Vault</h1>
                <span class="welcome">Active User: <strong><?php echo htmlspecialchars($_SESSION['username']); ?></strong></span>
            </div>
            <a href="logout.php" class="logout-btn">Logout</a>
        </div>

        <?php 
        if ($status === "success") echo "<div class='success'>".htmlspecialchars($message)."</div>";
        if ($status === "error") echo "<div class='error'>".htmlspecialchars($message)."</div>";
        ?>

        <div class="grid">
            <div class="box">
                <h3>Add New Entry</h3>
                <form method="POST" action="">
                    <input type="hidden" name="action" value="add_credential">
                    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                    
                    <label>Website Name / Resource</label>
                    <input type="text" name="site_name" placeholder="e.g. Google, GitHub" required autocomplete="off">
                    
                    <label>Username / Email</label>
                    <input type="text" name="site_username" placeholder="Username" required autocomplete="off">
                    
                    <label>Password</label>
                    <input type="password" name="site_password" placeholder="Password" required>
                    
                    <button type="submit">Secure Entry</button>
                </form>
            </div>

            <div class="box">
                <h3>Stored Logins</h3>
                
                <form method="GET" action="" class="search-box">
                    <input type="text" name="search" placeholder="Search by site or username..." value="<?php echo htmlspecialchars($search_query); ?>" autocomplete="off">
                    <button type="submit">Filter</button>
                </form>

                <table>
                    <thead>
                        <tr>
                            <th>Resource</th>
                            <th>Identity Identifier</th>
                            <th>Security Profile</th>
                            <th>Actions</th> </tr>
                    </thead>
                    <tbody>
                        <?php if (empty($credentials)): ?>
                            <tr>
                                <td colspan="4" class="no-data">No stored profiles found.</td>
                            </tr>
                        <?php else: ?>
                            <?php foreach ($credentials as $index => $row): ?>
                                <?php 
                                $display_password = ($row['decrypted_password'] !== null && $row['decrypted_password'] !== '') 
                                    ? $row['decrypted_password'] 
                                    : '[Decryption Error]';
                                ?>
                                <tr>
                                    <td><strong><?php echo htmlspecialchars($row['site_name']); ?></strong></td>
                                    <td><?php echo htmlspecialchars($row['site_username']); ?></td>
                                    <td>
                                        <div class="pass-container">
                                            <span class="pass-text" id="pass-<?php echo $index; ?>">••••••••</span>
                                            <button class="toggle-btn" onclick="togglePassword(<?php echo $index; ?>, '<?php echo htmlspecialchars(addslashes($display_password)); ?>')">Show</button>
                                            <button class="copy-btn" onclick="copyToClipboard(this, '<?php echo htmlspecialchars(addslashes($display_password)); ?>')">Copy</button>
                                        </div>
                                    </td>
                                    <td>
                                        <form method="POST" action="" class="delete-form" onsubmit="return confirm('Are you sure you want to delete the credentials for <?php echo htmlspecialchars(addslashes($row['site_name'])); ?>?');">
                                            <input type="hidden" name="action" value="delete_credential">
                                            <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                                            <input type="hidden" name="credential_id" value="<?php echo $row['id']; ?>">
                                            <button type="submit" class="delete-btn">Delete</button>
                                        </form>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <script>
    function togglePassword(index, plainPassword) {
        const passSpan = document.getElementById('pass-' + index);
        const btn = passSpan.nextElementSibling;
        
        if (passSpan.innerText === '••••••••') {
            passSpan.innerText = plainPassword;
            btn.innerText = 'Hide';
        } else {
            passSpan.innerText = '••••••••';
            btn.innerText = 'Show';
        }
    }

    function copyToClipboard(button, plainPassword) {
        if (plainPassword === '[Decryption Error]') {
            alert('Cannot copy an unreadable password.');
            return;
        }
        
        // Use the native Clipboard API
        navigator.clipboard.writeText(plainPassword).then(() => {
            const originalText = button.innerText;
            button.innerText = 'Copied!';
            button.style.background = '#059669';
            
            // Revert back after 1.2 seconds
            setTimeout(() => {
                button.innerText = originalText;
                button.style.background = '#10b981';
            }, 1200);
        }).catch(err => {
            console.error('Failed to copy text: ', err);
        });
    }
    </script>
</body>
</html>