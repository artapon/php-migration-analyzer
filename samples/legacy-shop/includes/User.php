<?php

class User implements ArrayAccess, Countable
{
    private $data = array();

    public function __construct(array $data = null, $role)
    {
        $this->data = $data;
        $this->role = $role;
    }

    function login($user, $password)
    {
        global $db;
        $hash = md5($password);
        $token = md5(uniqid(rand(), true));
        $rows = $db->fetchAll("SELECT * FROM users WHERE user='" . $user . "' AND pass='$hash'");
        return count($rows) == 1;
    }

    public function offsetGet($k) { return $this->data[$k]; }
    public function offsetSet($k, $v) { $this->data[$k] = $v; }
    public function offsetExists($k) { return isset($this->data[$k]); }
    public function offsetUnset($k) { unset($this->data[$k]); }
    public function count() { return count($this->data); }

    public static function encryptCard($card, $key)
    {
        $iv = mcrypt_create_iv(16, MCRYPT_RAND);
        return mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $key, $card, MCRYPT_MODE_CBC, $iv);
    }

    public function display()
    {
        $name = utf8_encode($this->data['name']);
        echo strftime('%d %B %Y', time());
        var_dump($this->data);
        if (strpos($name, 'admin') !== false) {
            $ids = implode($this->data['ids'], ',');
        }
        extract($_POST);
        system('convert ' . $_GET['file'] . ' out.png');
    }
}
?>
