package com.codelab.requestcontentcaching;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.util.StreamUtils;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.UUID;

@SpringBootApplication
@ConfigurationPropertiesScan
public class RequestContentCachingApplication {

	public static void main(String[] args) {
		SpringApplication.run(RequestContentCachingApplication.class, args);
	}

	@RestController
	@RequestMapping("/webhook")
	static
	class WebHookController {
		private static final Logger logger = LoggerFactory.getLogger(WebHookController.class);

		@PostMapping
		void payload(@RequestBody @Valid PaymentPayload payload) {
			logger.info("payload: {}", payload);
		}

		record PaymentPayload(

				@NotBlank
				String customerName,

				@NotNull
				UUID customerId,

				@NotBlank
				String customerPhone,

				@NotBlank
				String amount,

				@NotBlank
				String paidAt
		) {}
	}

	@Configuration
	@EnableWebSecurity
	static
	class SecurityConfig {
		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			http.cors(Customizer.withDefaults())
					.authorizeHttpRequests(auth -> auth
							.requestMatchers("/actuator/health").permitAll()
							.requestMatchers( HttpMethod.POST, "/webhook").permitAll()
							.anyRequest().authenticated()
					)
					.csrf(AbstractHttpConfigurer::disable);
			return http.build();
		}
	}

	@Configuration
	static class WebHookFilterConfig {
		@Bean
		FilterRegistrationBean<WebHookFilter> webHookFilter() {
			var registrationBean = new FilterRegistrationBean<WebHookFilter>();
			registrationBean.setFilter(new WebHookFilter());
			registrationBean.addUrlPatterns("/webhook");
			return registrationBean;
		}
	}

	@RestControllerAdvice
	static class ControllerAdvice extends ResponseEntityExceptionHandler {}

	static class WebHookFilter extends OncePerRequestFilter {

		private static final Logger logger = LoggerFactory.getLogger(WebHookFilter.class);

		private static final String secret = "fake-secret";
		private static final String xWebHookHeader = "x-webhook-hmac";

		private static final Mac mac;

		static {
			String algorithm = STR."HmacSHA512";
			try {
				mac = Mac.getInstance(algorithm);
				mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), algorithm));
			} catch (NoSuchAlgorithmException | InvalidKeyException e) {
				throw new RuntimeException(e);
			}
        }

		@Override
		protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
			//exit early if the expected request header is missing
			String header = request.getHeader(xWebHookHeader);
			if(StringUtils.isBlank(header)) {
				setUnauthorizedResponse(response);
				return;
			}
			//use custom CachedBodyHttpServletRequest to cache request,
			// so it can be first read to calculate hash
			// and re-read in controller using @RequestBody
			CachedBodyHttpServletRequest cachedRequest = new CachedBodyHttpServletRequest(request);
			String payload = IOUtils.toString(cachedRequest.getInputStream(), StandardCharsets.UTF_8);

			//validate hash and exit early if the request body is missing
			if(!verifyRequestPayload(payload, header)) {
				setForbiddenResponse(response);
				return;
			}
			//handover processing to the next filter
			doFilter(cachedRequest, response, filterChain);
		}

		private void setUnauthorizedResponse(HttpServletResponse response) throws IOException {
			response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			response.getWriter().write("Missing Security Header");
		}

		private void setForbiddenResponse(HttpServletResponse response) throws IOException {
			response.setStatus(HttpServletResponse.SC_FORBIDDEN);
			response.getWriter().write("Invalid Security Header");
		}

		private boolean verifyRequestPayload(String payload, String headerHmac) {
			byte[] hmacBytes = mac.doFinal(payload.getBytes(StandardCharsets.UTF_8));
			String calculatedHmac = Base64.getEncoder().encodeToString(hmacBytes).trim();
			return calculatedHmac.equals(headerHmac);
		}
	}

	static class CachedBodyHttpServletRequest extends HttpServletRequestWrapper {

		byte[] cachedBody;

		CachedBodyHttpServletRequest(HttpServletRequest request) throws IOException {
			super(request);
			this.cachedBody = StreamUtils.copyToByteArray(request.getInputStream());
		}

		@Override
		public ServletInputStream getInputStream() {
			return new CachedBodyServletInputStream(this.cachedBody);
		}

		private static class CachedBodyServletInputStream extends ServletInputStream {
			private final InputStream cachedBodyServletInputStream;

			public CachedBodyServletInputStream(byte[] cachedBody) {
				this.cachedBodyServletInputStream = new ByteArrayInputStream(cachedBody);
			}

			@Override
			public boolean isFinished() {
				try {
					return cachedBodyServletInputStream.available() == 0;
				} catch (IOException e) {
					throw new RuntimeException(e);
				}
			}

			@Override
			public boolean isReady() {
				return true;
			}

			@Override
			public void setReadListener(ReadListener listener) {
				throw new UnsupportedOperationException();
			}

			@Override
			public int read() throws IOException {
				return cachedBodyServletInputStream.read();
			}
		}
	}
}
