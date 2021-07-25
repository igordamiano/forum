package br.com.alura.forum.config.security;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import br.com.alura.forum.modelo.Usuario;
import br.com.alura.forum.repository.UsuarioRepository;

public class AutenticacaoViaTokenFilter extends OncePerRequestFilter {

	// Não dá pra injetar em classe de filtro com @Autowired, tem que ser via construtor
	private TokenService tokenService;
	private UsuarioRepository repository;
	
	public AutenticacaoViaTokenFilter(TokenService tokenService, UsuarioRepository repository) {
		this.tokenService = tokenService;
		this.repository = repository;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		
		// Recuperar token cabeçalho, validar e se tiver ok, autenticar no spring
		
		// Recuperar token cabeçalho
		String token = recuperarToken(request);
		
		// Validar o Token
		System.out.println("Token recuperado do cabeçalho: " + token);
		boolean valido = tokenService.isTokenValid(token);
		System.out.println("Token é váido: " + valido);
		
		// Se estiver válido, vai autenticar
		if (valido) {
			autenticarCliente(token);
		}
		
		filterChain.doFilter(request, response);
		
	}

	private void autenticarCliente(String token) {
		Long idUsuario = tokenService.getIdUsuario(token);
		Usuario usuario = repository.findById(idUsuario).get();
		
		// credencials é a senha, passando null, para o spring tanto faz que já validou antes
		UsernamePasswordAuthenticationToken authentication = new 
				UsernamePasswordAuthenticationToken(usuario, null, usuario.getAuthorities()); 
		
		SecurityContextHolder.getContext().setAuthentication(authentication);
		
	}

	private String recuperarToken(HttpServletRequest request) {
		
		String token = request.getHeader("Authorization");
		
		if (token == null || token.isEmpty() || !token.startsWith("Bearer ")) {
			return null;
		}
		return token.substring(7, token.length()); // 7 é o tamanho de "Bearer "
	}
	
	


}
