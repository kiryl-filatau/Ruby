require 'net/http'
require 'json'

class Vault
  attr_accessor :rt, :kb64

  def initialize(vault_host, vault_port, pki_name)
      @uri = URI.parse("http://#{vault_host}:#{vault_port}/v1/")
      @pki_name = "#{pki_name}"
  end

################## METHODS ####################

  def unseal!
    uri = URI.join(@uri, 'sys/unseal')
    req = Net::HTTP.new(uri.host, uri.port)
    headers = {"X-Vault-Token" => rt}
    data = { 'key' => kb64 }.to_json
    res = req.post(uri, data, headers)
    JSON.parse(res.body).to_hash
  end

  def mount_pki!
    uri = URI.join(@uri,'sys/mounts/', @pki_name)
    req = Net::HTTP.new(uri.host, uri.port)
    headers = {"X-Vault-Token" => rt}
    data = {"type": "pki"}.to_json
    res = req.post(uri, data, headers)
  end

  def upload_rootCA!
    uri = URI.join(@uri, @pki_name + '/config/ca')
    req = Net::HTTP.new(uri.host, uri.port)
    headers = {"X-Vault-Token" => rt}
    data = File.read('rootCA_key.json')
    res = req.post(uri, data, headers)
  end

  def create_role!(role_name)
    uri = URI.join(@uri, @pki_name + "/roles/#{role_name}")
    req = Net::HTTP.new(uri.host, uri.port)
    headers = {"X-Vault-Token" => rt}
    data = {"allowed_domains": ["example.com"],"allow_subdomains": true}.to_json
    res = req.post(uri, data, headers)
  end
 
  def issue_cert!(role_name, cert_name)
    uri = URI.join(@uri, @pki_name + "/issue/#{role_name}")
    req = Net::HTTP.new(uri.host, uri.port)
    headers = {"X-Vault-Token" => rt}
    data = {"common_name": "#{cert_name}"}.to_json
    res = req.post(uri, data, headers)
    response = JSON.parse(res.body)
  end

  def add_cert_to_kv!(cert_name, cert_sn, cert_pem)
    uri = URI.join(@uri, "secret/#{cert_name}")
    req = Net::HTTP.new(uri.host, uri.port)
    headers = {"X-Vault-Token" => rt}
    data = { "sn"=> "#{cert_sn}", "pem"=> "#{cert_pem}"}.to_json
    res = req.post(uri, data, headers)
  end

################### CHECKS #######################

  def health?
    uri = URI.join(@uri, 'sys/health')
    res = Net::HTTP.get(uri)
    JSON.parse(res).to_hash
  end

  def check_mounts?
    uri = URI.join(@uri, 'sys/mounts')
    req = Net::HTTP::Get.new(uri)
    req['X-Vault-Token'] = rt
    res = Net::HTTP.start(uri.hostname, uri.port) {|http|
      http.request(req)
    }
    JSON.parse(res.body).to_hash
  end

  def check_rootCA?
    uri = URI.join(@uri, @pki_name + '/ca')
    req = Net::HTTP::Get.new(uri)
    req['X-Vault-Token'] = rt
    res = Net::HTTP.start(uri.hostname, uri.port) {|http|
      http.request(req)
    }
  end

  def check_role?
    uri = URI.join(@uri, @pki_name + '/roles?list=true')
    req = Net::HTTP::Get.new(uri)
    req['X-Vault-Token'] = rt
    res = Net::HTTP.start(uri.hostname, uri.port) {|http|
      http.request(req)
    }
    JSON.parse(res.body).to_hash
  end

  def check_cert_in_kv?
    uri = URI.join(@uri, 'secret?list=true')
    req = Net::HTTP::Get.new(uri)
    req['X-Vault-Token'] = rt
    res = Net::HTTP.start(uri.hostname, uri.port) {|http|
      http.request(req)
    }
    JSON.parse(res.body).to_hash
  end

  def read_cert_from_kv?(cert_cname)
    uri = URI.join(@uri, "secret/#{cert_cname}")
    req = Net::HTTP::Get.new(uri)
    req['X-Vault-Token'] = rt
    res = Net::HTTP.start(uri.hostname, uri.port) {|http|
      http.request(req)
    }
    JSON.parse(res.body).to_hash
  end

    def read_cert_from_pki?(cert_sn)
    uri = URI.join(@uri, @pki_name + "/cert/#{cert_sn}")
    req = Net::HTTP::Get.new(uri)
    req['X-Vault-Token'] = rt
    res = Net::HTTP.start(uri.hostname, uri.port) {|http|
      http.request(req)
    }
    JSON.parse(res.body).to_hash
  end
end



############### TESTS ###################


test_attempt = 21

pki_name = "test#{test_attempt}_pki"
role_name = "test#{test_attempt}_role"
cert_cname = "test#{test_attempt}.example.com"

p v = Vault.new('54.165.255.89', 8200, "#{pki_name}")
v.rt = '4ec70c21-5e6e-585e-7440-b6c64b8060c7'
v.kb64 = 'r+mytS/Vfy5GVFZpj8Rs3VYnitgQ1vAIX8wlHYmciCc='


if v.health?['sealed']
  v.unseal!
  puts "unsealing..."
else
  puts "unsealed"
end

# p 'HEALTH' 
# p v.health?['sealed']
# p "====================="

if v.check_mounts?["#{pki_name}/"].nil? 
  v.mount_pki!
  puts "mounting pki..."
else
  puts "pki mounted"
end

# p "MOUNTS"
# p v.check_mounts?["#{pki_name}/"].nil?
# p "====================="

if (v.check_rootCA?.to_s).include? "HTTPOK"
  puts "CA uploaded"
else
  v.upload_rootCA!
  puts "uploading CA..."
end

# p 'ROOTCA'
# p (v.check_rootCA?.to_s).include? "HTTPOK"
# p "====================="

if (v.check_role?.key? 'data') && (v.check_role?["data"]["keys"].include? "#{role_name}")
  puts "role exists"
else
  v.create_role!("#{role_name}")
  puts "creating role..."
end

# p 'ROLE'
# p (v.check_role?.key? 'data') && (v.check_role?["data"]["keys"].include? "#{role_name}")
# p "====================="

if (v.check_cert_in_kv?.key? 'data') && (v.check_cert_in_kv?["data"]["keys"].include? "#{cert_cname}")
  puts "cert exists"
  cert_sn = v.read_cert_from_kv?("#{cert_cname}")['data']['sn']
  cert = v.read_cert_from_pki?("#{cert_sn}")['data']['certificate']
  cert_pem = v.read_cert_from_kv?("#{cert_cname}")['data']['pem']
  cert_json = {"pem_bundle"=> "#{cert_pem}#{cert}"}.to_json
  p cert_json
else
  response = v.issue_cert!("#{role_name}", "#{cert_cname}")
  v.add_cert_to_kv!("#{cert_cname}", response['data']['serial_number'], response['data']['private_key'])
  puts "adding to kv"
end

# p 'CERT'
# p (v.check_cert_in_kv?.key? 'data') && (v.check_cert_in_kv?["data"]["keys"].include? "#{cert_cname}")
# p "====================="

