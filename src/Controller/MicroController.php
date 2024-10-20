<?php
namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Yaml\Yaml;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\BinaryFileResponse;
use Symfony\Component\PasswordHasher\Hasher\NativePasswordHasher;

use Symfony\Component\HttpFoundation\Session\Session;

$session = new Session();

class MicroController extends AbstractController
{
    function getUsername(): String {
        $yaml =  Yaml::parse(file_get_contents(__DIR__.'/../../config/appconfig.yaml'));
        return isset($yaml['username']) ? $yaml['username'] : "username";
    }
    
    function getPassword(): String {
        $yaml =  Yaml::parse(file_get_contents(__DIR__.'/../../config/appconfig.yaml'));
        return isset($yaml['password']) ? $yaml['password'] : "password";
    }

    function getSetupDone(): Bool {
        $yaml =  Yaml::parse(file_get_contents(__DIR__.'/../../config/appconfig.yaml'));
        return isset($yaml['setup_done']) ? $yaml['setup_done'] : "false";
    }
    
    function getPublicFolder(): String {
        $yaml =  Yaml::parse(file_get_contents(__DIR__.'/../../config/appconfig.yaml'));
        $folders = $yaml['folders'];
        return isset($folders['public']) ? $folders['public'] : "../Documents/public";
    }
    
    function getPrivateFolder(): String {
        $yaml =  Yaml::parse(file_get_contents(__DIR__.'/../../config/appconfig.yaml'));
        $folders = $yaml['folders'];
        return isset($folders['private']) ? $folders['private'] : "../Documents/private";
    }

    function ScanDirectory($Directory) {
        $files = array();
        if (!file_exists($Directory)) {
	  return;
        }
        $MyDirectory = opendir($Directory);
        while($Entry = @readdir($MyDirectory)) {
          if(!is_dir($Directory."/".$Entry) && $Entry != '.' && $Entry != '..' && $Entry != 'index.*') {
            $enc = mb_detect_encoding($Entry, "UTF-8,ISO-8859-1,ISO-8859-15");
            $inc = iconv($enc, "UTF-8", $Entry);
            $files = array_merge($files, [$inc]);
          }
        }
        closedir($MyDirectory);
        natcasesort($files);
        return $files; 
    }

    function getHashedPassword($password): String {
        $passwordHasher = new NativePasswordHasher();
        return $passwordHasher->hash($password);
    }

    function isPasswordMatching($password): Bool {
        $passwordHasher = new NativePasswordHasher();
        return $passwordHasher->verify($this->getPassword(), $password);
    }

    #[Route('/', methods: ['GET'])]
    public function index(): Response {
        return $this->render('index.html');
    }

    #[Route('/setup', methods: ['GET'])]
    public function setup() {
        $setup_done = $this->getSetupDone();
        if ($setup_done){
          return $this->render('already_setup.html');
        }
        else{
          return $this->render('setup.html', [
            'public_folder' => $this->getPublicFolder(),
            'private_folder'=> $this->getPrivateFolder()
          ]);
        }
    }

    #[Route('/setup', methods:['POST'], name: 'setup')]
    public function postSetup(Request $request) {
        $username = $request->get('username');
        $password = $request->get('password');
        $config = array(
            'username' => $username,
            'password' => $this->getHashedPassword($password),
            'setup_done' => true,
            'folders' => array(
                'public' => $request->get('public_folder'),
                'private' => $request->get('private_folder')
            ),
        );
        $yaml = Yaml::dump($config, 2);
        file_put_contents(__DIR__.'/../../config/appconfig.yaml', $yaml);
        return $this->render('setup_done.html');
    }

    #[Route('/img/{img_name}', methods: ['GET'])]
    public function getImage($img_name) {
        if (!file_exists(__DIR__.'/../assets/'.$img_name)) {
            throw $this->createNotFoundException("Image not found.");
        }
        return new BinaryFileResponse(__DIR__.'/../assets/'.$img_name);
    }
      
    #[Route('/js/{script_name}', methods: ['GET'])]
    public function getJavascript($script_name) {
        if (!file_exists(__DIR__.'/../js/'.$script_name)) {
            throw $this->createNotFoundException("Script not found.");
        }
        return new BinaryFileResponse(__DIR__.'/../js/'.$script_name);
    }

    #[Route('/private', methods: ['GET'], name: "login")]
    public function login(Request $request, $login_error = NULL) {
        return $this->render('login.html', [
            'error' => $login_error
        ]);
    }

    #[Route('/private', methods: ['POST'], name: "login_check")]
    public function postLogin(Request $request) {
        if ($request->get("username") == $this->getUsername() &&
            $this->isPasswordMatching($request->get("password"))) {
                return $this->private();
        } else {
            $login_error = 'Invalid credentials.';
            return $this->login($request, $login_error);
        }
    }

    #[Route('/logout', name: "logout")]
    public function logout(Request $request) {
        return $this->redirect($this->generateUrl('login'));
    }

    #[Route('/public', methods: ['GET'])]
    public function public() {
        $entries = $this->ScanDirectory($this->getPublicFolder());
        return $this->render('list_public_files.html', array(
            'files' => $entries
        ));
    }
      
    #[Route('/public/{file_name}', methods: ['GET'])]
    public function getPublicFile($file_name) {
        $public = $this->getPublicFolder();
        if (!file_exists($public.'/'.$file_name)) {
          throw $this->createNotFoundException("File not found.");
        }
        return $this->file($public.'/'.$file_name);
    }

    public function private() {
        $entries = $this->ScanDirectory($this->getPrivateFolder());
        return $this->render('list_private_files.html', array(
            'files' => $entries
        ));
    }
      
    #[Route('/private/{file_name}', methods: ['GET'])]
    public function getPrivateFile($file_name) {
        $private = $this->getPrivateFolder();
        if (!file_exists($private.'/'.$file_name)) {
          throw $this->createNotFoundException("File not found.");
        }
        return $this->file($private.'/'.$file_name);
    }
}
