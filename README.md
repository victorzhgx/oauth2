**由于有Authorization Server - 授权服务器 和 Resource Server - 资源服务器 两个项目，我压缩了一下，解压导入即可，不要忘了在yml里面配置数据库~**

# Springboot+Springsecurity+Oauth2整合（用mysql实现持久化）

本文主要讲的是，实现oauth2的工作流程，需要对oauth2.0概念有一定的基础知识了解。阅读前请学习oauth2.0的理论知识。文末有此项目代码地址。

- **介绍**
- **建表**
- **权限和用户的建立**
- **Spring Security配置**
- **Oauth2 的配置**
 - Authorization Server - 授权服务器
 - Resource Server - 资源服务器
 

-------------------
##介绍
在github上许多关于用springsecurity搭建oauth2的Demo，但是几乎所有的都是把注册的Client放到内存中的，也就是带有**clients.inMemory()**这种代码的，项目启动时，会把这个Client初始化到内存中。你一定会看到以下代码：

```
public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
          clients.inMemory().withClient("client_1")
                  .authorizedGrantTypes("client_credentials", "refresh_token")
                  .scopes("select")
                  .authorities("oauth2")
                  .secret("123456");
}
```

**然而这样在生产环境肯定是不行的！因为我们要对客户开放注册Client！我们要实现Client的注册，动态的加载到Oauth服务中。**
所以要实现Client的持久化，本文用到的数据库是Mysql，表的建立是依照Oauth2标准来建立的。
**文末测试以Oauth2中grant_type=client_credentials为例说明**。

##建表
> **注：项目中有两个sql文件，在每次启动项目的时候会自动运行创建。若无需多次创建，可以直接删除这个两个文件即可**

要建立起Oauth2客户端，我们需要建立以下几张表：
oauth_client_details
oauth_client_token
oauth_access_token
oauth_refresh_token
oauth_code

我们以**‘product_api‘**命名resourceServer中的api请求路径，我们定义一个客户端叫做：read-write-client（认证权限类型：read，write）

```
INSERT INTO OAUTH_CLIENT_DETAILS(CLIENT_ID, RESOURCE_IDS, CLIENT_SECRET, SCOPE, AUTHORIZED_GRANT_TYPES, AUTHORITIES, ACCESS_TOKEN_VALIDITY, REFRESH_TOKEN_VALIDITY)
VALUES ('read-write-client', 'product-api','$2a$10$BurTWIy5NTF9GJJH4magz.9Bd4bBurWYG8tmXxeQh1vs7r/wnCFG2','read,write', 'client_credentials', 'ROLE_PRODUCT_ADMIN', 10800, 2592000);
#password [密码为加密后的“user”] :user 
```

##权限和用户的建立
SpringSecurity为我们提供了两个非常有用的接口：
 1. UserDetails-提供用户核心信息
 2. GrantedAuthority-授予身份验证对象以权限
 
我们向表中加入三个用户：

```
INSERT INTO authority  VALUES(1,'ROLE_OAUTH_ADMIN');
INSERT INTO authority VALUES(2,'ROLE_ADMIN_PRODUCT');
INSERT INTO authority VALUES(3,'ROLE_RESOURCE_ADMIN');
INSERT INTO credentials VALUES(1,b'1','oauth_admin','$2a$10$BurTWIy5NTF9GJJH4magz.9Bd4bBurWYG8tmXxeQh1vs7r/wnCFG2','0');
INSERT INTO credentials VALUES(2,b'1','resource_admin','$2a$10$BurTWIy5NTF9GJJH4magz.9Bd4bBurWYG8tmXxeQh1vs7r/wnCFG2','0');
INSERT INTO credentials  VALUES(3,b'1','user','$2a$10$BurTWIy5NTF9GJJH4magz.9Bd4bBurWYG8tmXxeQh1vs7r/wnCFG2','0');
INSERT INTO credentials_authorities VALUES (1, 1);
INSERT INTO credentials_authorities VALUES (2, 3);
INSERT INTO credentials_authorities VALUES (3, 2);
#Password : user
```

##Spring Security配置
![接下来，为了用户得到我们的认证权限，需要实现UserDetailsService接口](https://img-blog.csdn.net/20180812141138605?watermark/2/text/aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1ZpY3Rvcl9Bbg==/font/5a6L5L2T/fontsize/400/fill/I0JBQkFCMA==/dissolve/70)

通过继承WebSecurityConfigurerAdapter并用@EnableWebSecurity注解来实现安全保障。

```
package com.aak.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@EnableWebSecurity
@Configuration
public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {


    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    @Override
    public UserDetailsService userDetailsServiceBean() throws Exception {
        return new JdbcUserDetails();
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/webjars/**","/resources/**");

    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/login","/logout.do").permitAll()
                .antMatchers("/**").authenticated()
                .and()
                .formLogin()
                .loginProcessingUrl("/login.do")
                .usernameParameter("username")
                .passwordParameter("password")
                .loginPage("/login")
                .and()
                .logout()
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout.do"))
                .and()
                .userDetailsService(userDetailsServiceBean());
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsServiceBean())
        .passwordEncoder(passwordEncoder());
    }

}

```

##Oauth2 的配置
还需要建立两个组件：

 - Authorization Server - 授权服务器
 - Resource Server - 资源服务器
 
 ##Authorization Server - 授权服务器
授权服务器负责验证用户标识并提供令牌，使用@EnableAuthorizationServer注解启用授权服务器配置。

```
package com.aak.configuration;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.jdbc.DataSourceBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
import org.springframework.security.oauth2.provider.approval.JdbcApprovalStore;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.JdbcAuthorizationCodeServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;

import javax.sql.DataSource;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter {
    @Bean
    @ConfigurationProperties(prefix = "spring.datasource")
    public DataSource oauthDataSource() {
        return DataSourceBuilder.create().build();
    }

    @Bean
    public JdbcClientDetailsService clientDetailsService() {
        return new JdbcClientDetailsService(oauthDataSource());
    }

    @Bean
    public TokenStore tokenStore() {
        return new JdbcTokenStore(oauthDataSource());
    }

    @Bean
    public ApprovalStore approvalStore() {
        return new JdbcApprovalStore(oauthDataSource());
    }

    @Bean
    public AuthorizationCodeServices authorizationCodeServices() {
        return new JdbcAuthorizationCodeServices(oauthDataSource());
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.withClientDetails(clientDetailsService());
    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
        oauthServer.allowFormAuthenticationForClients();
        oauthServer.checkTokenAccess("permitAll()");
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints
                .approvalStore(approvalStore())
                .authorizationCodeServices(authorizationCodeServices())
                .tokenStore(tokenStore());
    }
}

```
在 **application.yml** 中配置一下数据库连接。
授权服务器配置成功后，我们启动项目，就能看到这个登陆界面。
输入用户名：oauth_admin     密码：user 登陆
![login](https://img-blog.csdn.net/20180808163603181?watermark/2/text/aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1ZpY3Rvcl9Bbg==/font/5a6L5L2T/fontsize/400/fill/I0JBQkFCMA==/dissolve/70)
ClientOpt
![Client](https://img-blog.csdn.net/20180808163625591?watermark/2/text/aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1ZpY3Rvcl9Bbg==/font/5a6L5L2T/fontsize/400/fill/I0JBQkFCMA==/dissolve/70)

##Resource Server - 资源服务器
资源服务器受保护于OAuth2令牌保护的资源（就是我们刚才配置的 product_api）。

```
package com.aak.configuration;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.jdbc.DataSourceBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;

import javax.sql.DataSource;

@EnableResourceServer
@Configuration
public class ResourcesServerConfiguration  extends ResourceServerConfigurerAdapter {

    @Bean
    @ConfigurationProperties(prefix="spring.datasource")
    public DataSource ouathDataSource(){return DataSourceBuilder.create().build();}

    @Override
    public void configure(ResourceServerSecurityConfigurer resources)throws Exception{

        TokenStore tokenStore=new JdbcTokenStore(ouathDataSource());
        resources.resourceId("product_api").tokenStore(tokenStore);

    }
    @Override

    public void configure(HttpSecurity http) throws Exception{


        http
                .authorizeRequests()
                .antMatchers(HttpMethod.GET, "/**").access("#oauth2.hasScope('read')")
                .antMatchers(HttpMethod.POST, "/**").access("#oauth2.hasScope('write')")
                .antMatchers(HttpMethod.PATCH, "/**").access("#oauth2.hasScope('write')")
                .antMatchers(HttpMethod.PUT, "/**").access("#oauth2.hasScope('write')")
                .antMatchers(HttpMethod.DELETE, "/**").access("#oauth2.hasScope('write')")
                .and()

                .headers().addHeaderWriter((request, response) -> {
            response.addHeader("Access-Control-Allow-Origin", "*");
            if (request.getMethod().equals("OPTIONS")) {
                response.setHeader("Access-Control-Allow-Methods", request.getHeader("Access-Control-Request-Method"));
                response.setHeader("Access-Control-Allow-Headers", request.getHeader("Access-Control-Request-Headers"));
            }
        });
    }
}
```
接下来我们就可以测试了！！！
**第一步**：我们启动AuthorizationServer，用账号：oauth_admin  密码：user 登陆。
可以看到**OAuth Server Administration Dashboard**这个界面，可以在这里添加客户端，比如我们这里建立一个grant_type 包括 **client_credentials**的客户端。
![这是我们建立好的一个Client](https://img-blog.csdn.net/20180813122752950?watermark/2/text/aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1ZpY3Rvcl9Bbg==/font/5a6L5L2T/fontsize/400/fill/I0JBQkFCMA==/dissolve/70)

请求resourceServive时，这里我们用firefox里面的RESTClient测试：
```
http://localhost:8080/oauth/token?grant_type=client_credentials&client_id=newtest&client_secret=user
```
![这里写图片描述](https://img-blog.csdn.net/20180813123028112?watermark/2/text/aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1ZpY3Rvcl9Bbg==/font/5a6L5L2T/fontsize/400/fill/I0JBQkFCMA==/dissolve/70)
我们从返回的json里面可以直接获取到 access_token！

**第二步**：我们用另一台机器启动ResourceServer（或者可以换一个端口来启动），拿着我们刚刚获取到的token去请求我们需要的资源。
首先我们不带access_token，直接请求资源路径：
![结果](https://img-blog.csdn.net/20180813123717152?watermark/2/text/aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1ZpY3Rvcl9Bbg==/font/5a6L5L2T/fontsize/400/fill/I0JBQkFCMA==/dissolve/70)
**我们会看到时没有权限访问的。**
接下来我们带着用刚才获取到的access_token去访问资源。
![结果](https://img-blog.csdn.net/20180813123925870?watermark/2/text/aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1ZpY3Rvcl9Bbg==/font/5a6L5L2T/fontsize/400/fill/I0JBQkFCMA==/dissolve/70)
**可以看到我们成功的访问到了受保护的资源！！！**
代码地址：https://github.com/victorzhgx/oauth2
