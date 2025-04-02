create database if not exists shaomai;
use shaomai;
CREATE TABLE antijs_configs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    create_time DATETIME DEFAULT CURRENT_TIMESTAMP,
    update_time DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    api_name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    user_name VARCHAR(255) NOT NULL,
    source_website VARCHAR(255) NOT NULL,
    hijack_js_url TEXT NOT NULL,
    breakpoint_line_num INT NOT NULL,
    breakpoint_col_num INT NOT NULL,
    target_func VARCHAR(255) NOT NULL,
    params_len INT,
    params_example TEXT,
    expire_time DATETIME,
    max_calls INT,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    override_funcs VARCHAR(255) DEFAULT 'setTimeout,setInterval',
    trigger_js TEXT,
    cookies TEXT,
    INDEX idx_api_name (api_name),
    INDEX idx_is_active (is_active)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;