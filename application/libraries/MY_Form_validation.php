<?php if (!defined('BASEPATH')) exit('No direct script access allowed');
/**
 * CSRF
 *
 * Cross Site Request Forgery library for Code Igniter.
 *
 * @package		CSRF
 * @author		Lukasz Karpuk (http://www.freshwebtrends.com)
 * @version		1.0.0
 * @license		MIT License Copyright (c) 2012 Lukasz Karpuk
 */
 
class MY_Form_validation extends CI_Form_validation{

	private $hash = "";
	private $html = "";
	private $time = "";
	
	public function MY_Form_validation()
    {
		$this->ci =& get_instance();	
		$this->ci->load->library('encrypt');	
		$this->ci->load->helper('form');		
    }

	/**
	 * Method to generate encrypted csrf token and output html hidden fields or just token
	 */
	public function create_csrf($timestamp, $method = "standard", $outputHTML = true){
		$key = $this->ci->config->item('encryption_key');	
		$this->time = $timestamp;
		//if method is not passed use sha1(standard) by default
		//otherwise use codeigniter encryption method
		switch($method){
			case "standard":
				$this->hash = sha1($this->time + $key);
				break;
			case "secure":
				$this->hash = $this->ci->encrypt->encode($this->time);
				break;
			default:
				$this->hash = sha1($this->time + $key);
				break;
		}

		//determine the output type...if false return just the hash
		//if true, return 2 html hidden input fields
		if($outputHTML == false){
			return $this->hash;
		}else{
			$this->html .= '<input type="hidden" id="csrf" name="csrf" value="' . $timestamp . '" />';
			$this->html .= '<input type="hidden" id="csrf_token" name="csrf_token" value="' . $this->hash . '" />';
			return $this->html;
		}		
	}
	
	public function validate_csrf($method = "standard"){
		$key = $this->ci->config->item('encryption_key');
		$timestamp = $this->ci->input->post('csrf', true);
		$new_hash = "";
		$decryptedTimestamp = "";
		$passed_token = $this->ci->input->post('csrf_token', TRUE);
		
		//create the new hash based on encryption method
		switch($method){
			case "standard":
				$new_hash = sha1($timestamp  + $key);
				break;
			case "secure":
				$decryptedTimestamp = $this->ci->encrypt->decode($passed_token);
				break;
			default:
				$new_hash = sha1($timestamp  + $key);
				break;
		}
		
		//compare hashes or timestamps and return true or false
		if($method == "standard"){
			if($new_hash == $passed_token){
				return true;
			}else{
				return false;
			}
		}else if($method == "secure"){
			if($timestamp == $decryptedTimestamp){
				return true;
			}else{
				return false;
			}
		}else{
			if($new_hash == $passed_token){
				return true;
			}else{
				return false;
			}
		}
	}
}
/* End of file MY_Form_validation.php */
/* Location: ./application/libraries/MY_Form_validation.php */