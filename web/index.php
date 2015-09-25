<?php
require_once __DIR__.'/../vendor/autoload.php';

$app = new Silex\Application();
$app['debug'] = true;


use Symfony\Component\Yaml\Yaml;
$yaml =  Yaml::parse(file_get_contents(__DIR__.'/config.yml'));
$username = $yaml['username'];
$password= $yaml['password'];
$setup_done = $yaml['setup_done'];
$folders = $yaml['folders'];
$private = $folders['private'];
$public = $folders['public'];

$app['security.firewalls'] = array(
  'admin' => array(
    'pattern' => '/private',
    'form' => array('login_path' => '/login', 'check_path' => '/private/login_check'),
    'logout' => array('logout_path' => '/private/logout', 'invalidate_session' => true),
    'users' => array(
      $username => array('ROLE_ADMIN', $password)
    )
  )
);
$app->register(new Silex\Provider\SecurityServiceProvider());

$app->register(new Silex\Provider\SessionServiceProvider());
$app->register(new Silex\Provider\UrlGeneratorServiceProvider());
$app->register(new Silex\Provider\TwigServiceProvider(), array(
  'twig.path' => __DIR__.'/views',
));

function ScanDirectory($Directory){
  $files = array();
  if (!file_exists($Directory)) {
    mkdir($Directory, 0755, true);
  }
  $MyDirectory = opendir($Directory);
  while($Entry = @readdir($MyDirectory)) {
    if(!is_dir($Directory."/".$Entry) && $Entry != '.' && $Entry != '..' && $Entry != 'index.*') {
      $enc = mb_detect_encoding($Entry, "UTF-8,ISO-8859-1,ISO-8859-15");
      $inc = iconv($enc, "ISO-8859-15", $Entry);
      $files = array_merge($files, [$inc]);
    }
  }
  closedir($MyDirectory);
  natcasesort($files);
  return $files;

};

use Symfony\Component\HttpFoundation\Request;

$app->get('/', function() use($app) {
  return $app['twig']->render('index.html');
});

$app->get('/setup', function() use ($app, $setup_done) {
  if ($setup_done == true){
    return $app['twig']->render('setup_done.html');
  }
  else{
    return $app['twig']->render('setup.html');
  }
});

$app->post('/setup', function(Request $request) use ($app, $private, $public, $password) {
  $username = $request->get('username');
  $passwd= $request->get('password');
  $password = (new \Symfony\Component\Security\Core\Encoder\MessageDigestPasswordEncoder())->encodePassword($passwd, '');
  $config = array(
    'username' => $username,
    'password' => $password,
    'setup_done' => true,
    'folders' => array(
      'private' => $private,
      'public' => $public
    ),
  );
  $yaml = Yaml::dump($config, 2);
  file_put_contents(__DIR__.'/config.yml', $yaml);
  return "";
})
  ->bind('setup');

$app->get('/img/{img_name}', function($img_name) use ($app) {
  if (!file_exists(__DIR__.'/assets/'.$img_name)) {
    $app->abort(404);
  }
  return $app->sendFile(__DIR__.'/assets/'.$img_name);
});

$app->get('/js/{script_name}', function($script_name) use ($app) {
  if (!file_exists(__DIR__.'/js/'.$script_name)) {
    $app->abort(404);
  }
  return $app->sendFile(__DIR__.'/js/'.$script_name);
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
    'files' => $entries
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
    'files' => $entries
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
