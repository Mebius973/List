<?php
require_once __DIR__.'/../vendor/autoload.php';

// storage of password and private and public paths
$username='admin';
$passwd='5FZ2Z8QIkA7UTZ4BYkoC+GsReLf569mSKDsfods6LYQ8t+a8EW9oaircfMpmaLbPBh4FOBiiFyLfuZmTSUwzZg==';
$private='../../Documents';
$public='../../Documents/public';
$setup_done = false;

$app = new Silex\Application();
$app['debug'] = true;

$app['security.firewalls'] = array(
  'admin' => array(
    'pattern' => '/private',
    'form' => array('login_path' => '/login', 'check_path' => '/private/login_check'),
    'logout' => array('logout_path' => '/private/logout', 'invalidate_session' => true),
    'users' => array(
      'admin' => array('ROLE_ADMIN', $passwd),
    ),
  ),
);
$app->register(new Silex\Provider\SecurityServiceProvider());

$app->register(new Silex\Provider\SessionServiceProvider());
$app->register(new Silex\Provider\UrlGeneratorServiceProvider());
$app->register(new Silex\Provider\TwigServiceProvider(), array(
  'twig.path' => __DIR__.'/views',
));

function ScanDirectory($Directory){
  $files = array();
  $folders = array();
  $MyDirectory = opendir($Directory) or die('Erreur');
  while($Entry = @readdir($MyDirectory)) {
    if($Entry != '.' && $Entry != '..' && $Entry != 'index.*') {
      $enc = mb_detect_encoding($Entry, "UTF-8,ISO-8859-1,ISO-8859-15");
      $inc = iconv($enc, "ISO-8859-15", $Entry);
      if(is_dir($Directory."/".$Entry) ){
        $folders = array_merge($folders, [$inc]);
      }
      else{
        $files = array_merge($files, [$inc]);
      }
    }
  }
  closedir($MyDirectory);

  natcasesort($folders);
  natcasesort($files);
  $entries[0] = $folders;
  $entries[1] = $files;

  return $entries;
};

use Symfony\Component\HttpFoundation\Request;

$app->get('/', function() use($app) {
  return $app['twig']->render('index.html');
});

use Silex\Application\SecurityTrait;

// !---- This part helps generating a password which has to be replaced manually ----! //

$app->get('/pwd/{password}', function($password) use($app) {
  return (new \Symfony\Component\Security\Core\Encoder\MessageDigestPasswordEncoder())->encodePassword($password, '');
});

// !---- ----! //

$app->get('/setup', function() use ($app) {
  return $app['twig']->render('setup.html');
});

$app->post('/setup', function(Request $request) use ($app, $private, $public, $passwd, $setup_done) {
  $username = $request->get('username');
  $check_password= $request->get('check_password');
  $password= $request->get('password');
  // a simple js check could be nice here
  if ($check_password != $password){
    return "Passwsord didn't match";
  }
  else{
    $count = count(array_keys($app['security.firewalls']['admin']['users']));
    echo $username."<br />";
    $passwd =  (new \Symfony\Component\Security\Core\Encoder\MessageDigestPasswordEncoder())->encodePassword($password, '');
    array_keys($app['security.firewalls']['admin']['users'])[$count] = $username;
    array_values($app['security.firewalls']['admin']['users'])[$count] = array('ROLE_ADMIN', $passwd);
    //array_merge($app['security.firewalls']['admin']['users'], array($username => array('ROLE_ADMIN', $passwd))); 
    $app->register(new Silex\Provider\SecurityServiceProvider());
    echo array_keys($app['security.firewalls']['admin']['users'])[$count];
    echo " => ";
    echo count(array_values($app['security.firewalls']['admin']['users'])); 
    return "";
   
  }
})
  ->bind('setup');

$app->get('/img/{img_name}', function($img_name) use ($app) {
  if (!file_exists(__DIR__.'/assets/'.$img_name)) {
    $app->abort(404);
  }

  return $app->sendFile(__DIR__.'/assets/'.$img_name);
});

$app->get('/login', function(Request $request) use ($app) {
  return $app['twig']->render('login.html', array(
    'error'         => $app['security.last_error']($request),
    'last_username' => $app['session']->get('_security.last_username'),
  ));
});

$app->get('/public', function() use($app, $public) {
  $entries = ScanDirectory($public);
  return $app['twig']->render('list_public_files.html', array(
    'folders' => $entires[0],    
    'files' => $entries[1],
  ));
});

$app->get('/public/{file_name}', function($file_name) use ($app, $public) {
  if (!file_exists($public.'/'.$file_name)) {
    $app->abort(404);
  }
  return $app->sendFile($public.'/'.$file_name);
});

$app->get('/private', function() use($app, $private) {
  $entries = ScanDirectory($private);
  return $app['twig']->render('list_private_files.html', array(
    'folders' => $entries[0],    
    'files' => $entries[1],
  ));
});

$app->get('/private/{file_name}', function($file_name) use ($app, $private) {
  if (!file_exists($private.'/'.$file_name)) {
    $app->abort(404);
  }

  return $app->sendFile($private.'/'.$file_name);
});

$app->run();
?>
