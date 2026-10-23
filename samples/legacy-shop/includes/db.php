<?php
/*
 * Legacy DB layer (PHP 5.2 era). This comment mentions mysql_query() but
 * must NOT be reported because it is a comment.
 */
define('DB_HOST', 'localhost', true);
$db_password = 'S3cretPass';

class Database
{
    var $link;
    var $lastError;

    function Database($host, $user = 'root', $pass)
    {
        $this->link = mysql_connect($host, $user, $pass) or die(mysql_error());
        mysql_select_db('shop', $this->link);
        $this->connectedAt = time();
    }

    function query($sql)
    {
        $result = @mysql_query($sql, $this->link);
        if (!$result) {
            $this->lastError = $php_errormsg;
        }
        return $result;
    }

    function fetchAll($sql)
    {
        $rows = array();
        $r = $this->query($sql);
        while ($row = mysql_fetch_assoc($r)) {
            $rows[] = $row;
        }
        return $rows;
    }

    function escape($s)
    {
        if (get_magic_quotes_gpc()) {
            $s = stripslashes($s);
        }
        return mysql_real_escape_string($s);
    }
}

function __autoload($class)
{
    require_once dirname(__FILE__) . '/' . $class . '.php';
}

$db =& new Database(DB_HOST, 'root', $db_password);
