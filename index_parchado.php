<?php
function loadDatabaseSettings($pathjs){
        $string = file_get_contents($pathjs);
        $json_a = json_decode($string, true); 
        return $json_a;
}
function validarJSON($jsB, $esperados) {
	foreach ($jsB as $clave => $valor) {
		if (!in_array($clave, $esperados)) {
			return false;
		}
	}
	return true;
}
function getToken(){
	//creamos el objeto fecha y obtuvimos la cantidad de segundos desde el 1ª enero 1970
	$fecha = date_create();
	$tiempo = date_timestamp_get($fecha);
	//vamos a generar un numero aleatorio
	$numero = mt_rand();
	//vamos a generar ua cadena compuesta
	$cadena = ''.$numero.$tiempo;
	// generar una segunda variable aleatoria
	$numero2 = mt_rand();
	// generar una segunda cadena compuesta
	$cadena2 = ''.$numero.$tiempo.$numero2;
	// generar primer hash en este caso de tipo sha1
	$hash_sha1 = sha1($cadena);
	// generar segundo hash de tipo MD5 
	$hash_md5 = md5($cadena2);
	return substr($hash_sha1,0,20).$hash_md5.substr($hash_sha1,20);
}
 
require 'vendor/autoload.php';
$f3 = \Base::instance();
$f3->route('GET /',
        function() {
                echo 'Hello, World:';
        }
); 
$f3->route('GET /saludo/@nombre',
    function($f3) {
        echo 'Hola  '.$f3->get('PARAMS.nombre');
    }
);
// REGISTRO 
$f3->route('POST /Registro', function($f3) {
    $dbcnf = loadDatabaseSettings('db.json');
    $db = new \DB\SQL(
        'mysql:host=localhost;port=' . $dbcnf['port'] . ';dbname=' . $dbcnf['dbname'],
        $dbcnf['user'],
        $dbcnf['password']
    );
    $db->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);

    // Obtener datos del JSON recibido
    $input = json_decode($f3->get('BODY'), true);

    // Verificar que todos los campos esperados existen
    $esperados = ['uname', 'email', 'password'];
    foreach ($esperados as $campo) {
        if (!isset($input[$campo]) || empty(trim($input[$campo]))) {
            http_response_code(400);
            echo json_encode(["error" => "Falta o vacio el campo: $campo"]);
            return;
        }
    }

    // Obtener valores
    $uname = $input['uname'];
    $email = $input['email'];
    $password = $input['password'];

    // Validar formato de email
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        http_response_code(400);
        echo json_encode(["error" => "Correo electronico no valido"]);
        return;
    }

    // Hashear la contraseña de forma segura
    $hash = password_hash($password, PASSWORD_DEFAULT);

    try {
        // Usar consultas preparadas para evitar inyecciones SQL
        $stmt = $db->prepare("INSERT INTO Usuario (uname, email, password) VALUES (?, ?, ?)");
        $stmt->execute([$uname, $email, $hash]);

        echo json_encode(["success" => true]);
    } catch (PDOException $e) {
        http_response_code(500);
        echo json_encode(["error" => "Error al registrar el usuario."]);
    }
});


$f3->route('POST /Login',
	function($f3) {
		$dbcnf = loadDatabaseSettings('db.json');
		$db=new DB\SQL(
			'mysql:host=localhost;port='.$dbcnf['port'].';dbname='.$dbcnf['dbname'],
			$dbcnf['user'],
			$dbcnf['password']
		);
		$db->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
		/////// obtener el cuerpo de la peticion
		$Cuerpo = $f3->get('BODY');
		$jsB = json_decode($Cuerpo,true);
		/////////////
		$R = array_key_exists('uname',$jsB) && array_key_exists('password',$jsB);
		// TODO checar si estan vacio los elementos del json
		if (!$R){
			echo '{"R":-1}';
			return;
		}
		// TODO validar correo en json
		// TODO Control de error de la $DB
		try {
			$R = $db->exec('Select id from  Usuario where uname ="'.$jsB['uname'].'" and password = md5("'.$jsB['password'].'");');
		} catch (Exception $e) {
			echo '{"R":-2}';
			return;
		}
		if (empty($R)){
			echo '{"R":-3}';
			return;
		}
		$T = getToken();
		//file_put_contents('/tmp/log','insert into AccesoToken values('.$R[0].',"'.$T.'",now())');
		$db->exec('Delete from AccesoToken where id_Usuario = "'.$R[0]['id'].'";');
		$R = $db->exec('insert into AccesoToken values('.$R[0]['id'].',"'.$T.'",now())');
		echo "{\"R\":0,\"D\":\"".$T."\"}";
	}
);
$f3->route('POST /Imagen',
    function($f3) {
        // Crear directorios si no existen
        if (!file_exists('tmp')) {
            mkdir('tmp');
        }
        if (!file_exists('img')) {
            mkdir('img');
        }

        // Obtener y decodificar el cuerpo de la petición
        $Cuerpo = $f3->get('BODY');
        $jsB = json_decode($Cuerpo, true);

        // Verificar que todos los campos requeridos existen y no están vacíos
        $camposRequeridos = ['name', 'data', 'ext', 'token'];
        foreach ($camposRequeridos as $campo) {
            if (!isset($jsB[$campo]) || trim($jsB[$campo]) === '') {
                echo json_encode(["R" => -1, "error" => "Falta o vacío el campo: $campo"]);
                return;
            }
        }

        // Validar extensión permitida
        $extensionesPermitidas = ['jpg', 'jpeg', 'png', 'gif'];
        if (!in_array(strtolower($jsB['ext']), $extensionesPermitidas)) {
            echo json_encode(["R" => -2, "error" => "Extensión no permitida"]);
            return;
        }

        // Cargar configuración de la base de datos
        $dbcnf = loadDatabaseSettings('db.json');
        $db = new DB\SQL(
            'mysql:host=localhost;port=' . $dbcnf['port'] . ';dbname=' . $dbcnf['dbname'],
            $dbcnf['user'],
            $dbcnf['password']
        );
        $db->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);

        // Validar token
        $TKN = $jsB['token'];
        try {
            $stmt = $db->prepare('SELECT id_Usuario FROM AccesoToken WHERE token = ?');
            $stmt->execute([$TKN]);
            $resultado = $stmt->fetch();
            if (!$resultado) {
                echo json_encode(["R" => -3, "error" => "Token inválido"]);
                return;
            }
            $id_Usuario = $resultado['id_Usuario'];
        } catch (Exception $e) {
            echo json_encode(["R" => -4, "error" => "Error al validar el token"]);
            return;
        }

        // Guardar imagen temporal
        $tmpPath = 'tmp/' . $id_Usuario;
        file_put_contents($tmpPath, base64_decode($jsB['data']));

        // Insertar metadatos de la imagen en la base de datos
        try {
            $stmt = $db->prepare('INSERT INTO Imagen (name, ruta, id_Usuario) VALUES (?, ?, ?)');
            $stmt->execute([$jsB['name'], 'img/', $id_Usuario]);

            $idImagen = $db->lastInsertId();

            // Actualizar ruta con nombre de archivo final
            $rutaFinal = 'img/' . $idImagen . '.' . $jsB['ext'];
            $stmt = $db->prepare('UPDATE Imagen SET ruta = ? WHERE id = ?');
            $stmt->execute([$rutaFinal, $idImagen]);

            // Mover archivo a su nueva ubicación
            rename($tmpPath, $rutaFinal);

            echo json_encode(["R" => 0, "D" => $idImagen]);
        } catch (Exception $e) {
            echo json_encode(["R" => -6, "error" => "Error al guardar en la base de datos", "detalle" => $e->getMessage()]);
        }
    }
);

$f3->route('POST /Descargar',
		function($f3) {
		$dbcnf = loadDatabaseSettings('db.json');
		$db=new DB\SQL(
			'mysql:host=localhost;port='.$dbcnf['port'].';dbname='.$dbcnf['dbname'],
			$dbcnf['user'],
			$dbcnf['password']
		);
		$db->setAttribute(\PDO:: ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
		//obtener el cuerpo de la peticion
		$Cuerpo = $f3->get('BODY');
		$jsB = json_decode($Cuerpo,true);
		///////////////////////////////
		$R = array_key_exists('token',$jsB) && array_key_exists('id',$jsB);
		// TODO checar si estan vacios los elemento del json
		// TODO control de error
		if (!$R){
			echo '{"R":-1}';
			return;
		}

		//TODO VALIDAR CORREO EN JSON
		// Comprobar que el usuario sea valido
		$TKN = $jsB['token'];
		$idImagen = $jsB['id'];
		try {
			$R = $db->exec('select id_Usuario from AccesoToken where token = "'.$TKN.'"');
		}catch (Exception $e){
			echo '{"R":-2}';
			return;
		}
		// Buscar imagen y enviarla
		try {
			$R = $db->exec('Select name,ruta from Imagen where id = '.$idImagen);  
			if(empty($R)) {
				echo'{"R":-3, "msg": "Imagen no encontrada"}';
				return;
			}
		}
		catch (Exception $e){
			echo '{"R":-3, "msg": "Error en la consulta: '.$e->getMessage().'"}';
			return;
		}
		$web = \Web::instance();
		ob_start();
		//send the file without any download dialog
		$info = pathinfo($R[0]['ruta']);
		$web->send($R[0]['ruta'],NULL,0,TRUE,$R[0]['name'].'.'.$info['extension']);
		$out=ob_get_clean();
		//echo "{\"R\":0,\"D\":\"".$T."\"}";
	    }
);
$f3->run();
?>
