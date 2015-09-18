<?php
require_once __DIR__.'/../vendor/autoload.php';

$app = new Silex\Application();
$app['debug'] = true;

$app->register(new Silex\Provider\SecurityServiceProvider(), array(
  'security.firewalls' => array(
    'admin' => array(
      'pattern' => '/private',
      'form' => array('login_path' => '/login', 'check_path' => '/private/login_check'),
      'logout' => array('logout_path' => '/private/logout', 'invalidate_session' => true),
      'users' => array(
        'admin' => array('ROLE_ADMIN', '5FZ2Z8QIkA7UTZ4BYkoC+GsReLf569mSKDsfods6LYQ8t+a8EW9oaircfMpmaLbPBh4FOBiiFyLfuZmTSUwzZg=='),
      ),
    ),
  ),
));

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

/*
$app->get('/', function() use($app)) {
  if ($app['security']->isGranted('IS_AUTHENTICATED_ANONYMOUSLY') {
    $subRequest = Request::create('/public', 'GET');
    return $app->handle($subRequest, HttpKernelInterface::SUB_REQUEST);
  }
  else {
    $subRequest = Request::create('/private', 'GET');
    return $app->handle($subRequest, HttpKernelInterface::SUB_REQUEST);
  }
};
 */

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

$app->get('/public', function() use($app) {
  $entries = ScanDirectory('../../Documents/public');
  return $app['twig']->render('list_public_files.html', array(
    'folders' => $entires[0],    
    'files' => $entries[1],
  ));
});

$app->get('/public/{file_name}', function($file_name) use ($app) {
  if (!file_exists('../../Documents/public/'.$file_name)) {
    $app->abort(404);
  }

  return $app->sendFile('../../Documents/public/'.$file_name);
});

$app->get('/private', function() use($app) {
  $entries = ScanDirectory('../../Documents');
  return $app['twig']->render('list_private_files.html', array(
    'folders' => $entries[0],    
    'files' => $entries[1],
  ));
});

$app->get('/private/{file_name}', function($file_name) use ($app) {
  if (!file_exists('../../Documents/'.$file_name)) {
    $app->abort(404);
  }

  return $app->sendFile('../../Documents/'.$file_name);
});

$app->run();
?>
