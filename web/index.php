<?php
require_once __DIR__.'/../vendor/autoload.php';

$app = new Silex\Application();
$app['debug'] = true;
// ... definitions

function ScanDirectory($Directory){
  $entries = array();
  $MyDirectory = opendir($Directory) or die('Erreur');
  while($Entry = @readdir($MyDirectory)) {
    if(!is_dir($Directory.'/'.$Entry)&& $Entry != '.' && $Entry != '..' && $Entry != 'index.*') {
      $enc = mb_detect_encoding($Entry, "UTF-8,ISO-8859-1,ISO-8859-15");
      $inc = iconv($enc, "ISO-8859-15", $Entry);
      $entries = array_merge($entries, [$inc]);
    }
  }
  closedir($MyDirectory);
  natcasesort($entries);
  foreach($entries as $entry){
    echo '<li><a href="http://geoffroy.iiens.net/'.$entry.'">'.$entry.'</a></li>';
  }
}

$app->get('/list', function() use($app){
  ScanDirectory('../../Documents');
  return "";
});

$app->run();
?>
