package br.com.alura.forum.config.security;

import java.util.Date;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import br.com.alura.forum.modelo.Usuario;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Service
public class TokenService {
	
	@Value("${forum.jwt.expiration}")
	private String expiration;
	
	@Value("${forum.jwt.secret}")
	private String secret;


	public String gerarToken(Authentication authentication) {
		Usuario logado = (Usuario) authentication.getPrincipal();
		Date hoje = new Date();
		Date dataExpiracao = new Date(hoje.getTime() + Long.parseLong(expiration));
		
		return Jwts.builder()
				.setIssuer("API do Forum Igor") //Quem gerou o token
				.setSubject(logado.getId().toString()) // Usuário autenticado, o dono do token 
				.setIssuedAt(hoje) // data de geração do Token
				.setExpiration(dataExpiracao) // data que vai expirar
				.signWith(SignatureAlgorithm.HS256, secret)
				.compact(); 
	}


	public boolean isTokenValid(String token) {
		
		try {
			Jwts.parser()
			.setSigningKey(this.secret) // passa a nossa chave a aplicação para cryptografar e descryptografar
			.parseClaimsJws(token); // recupera o token e informações setadas no token
			
			// Token está válido
			return true;
		} catch (Exception e) {
			// token nulo, token inválido....
			return false;
		}
	}


	public Long getIdUsuario(String token) {
		Claims body = Jwts.parser()
		.setSigningKey(this.secret) // passa a nossa chave a aplicação para cryptografar e descryptografar
		.parseClaimsJws(token) // recupera o token e informações setadas no token
		.getBody();
		
		return Long.parseLong(body.getSubject());
		
	}

}
