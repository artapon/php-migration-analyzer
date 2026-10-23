<?
include 'includes/db.php';
session_start();
session_register('cart');

$id = $HTTP_GET_VARS['id'];
$sort = isset($_GET['sort']) ? $_GET['sort'] : 'name';

if (eregi("^[0-9]+$", $id)) {
    $res = mysql_query("SELECT * FROM products WHERE id = $id");
    $product = mysql_fetch_array($res);
}

$tags = split(",", $product['tags']);
$first = $product['name']{0};
$label = $product['stock'] == 0 ? 'Sold out' : $product['stock'] < 5 ? 'Low stock' : 'In stock';
echo "Total: " . $product['price'] + $product['shipping'];

$cart = unserialize($_COOKIE['cart']);
while (list($k, $v) = each($cart)) {
    echo "Item ${k}: $v<br>";
}

$sorter = create_function('$a,$b', 'return strcmp($a["name"], $b["name"]);');
usort($products, $sorter);

$html = preg_replace('/\[b\](.*?)\[\/b\]/e', "'<b>'.strtoupper('$1').'</b>'", $product['description']);
?>
<html>
<body>
<h1><?php echo $product['name']; ?></h1>
<p>Search: <?php echo $_GET['q']; ?></p>
<form action="<?php echo $_SERVER['PHP_SELF']; ?>" method="post">
  <input type="submit" value="Add to cart">
</form>
<?php include $_GET['page'] . '.php'; ?>
</body>
</html>
