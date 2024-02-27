/*
 * Copyright (c) 2024 Contributors to the Eclipse Foundation.
 * Copyright (c) 2015, 2020 Oracle and/or its affiliates and others.
 * All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0, which is available at
 * http://www.eclipse.org/legal/epl-2.0.
 *
 * This Source Code may also be made available under the following Secondary
 * Licenses when the conditions for such availability set forth in the
 * Eclipse Public License v. 2.0 are satisfied: GNU General Public License,
 * version 2 with the GNU Classpath Exception, which is available at
 * https://www.gnu.org/software/classpath/license.html.
 *
 * SPDX-License-Identifier: EPL-2.0 OR GPL-2.0 WITH Classpath-exception-2.0
 */

package org.glassfish.soteria.cdi;

import static java.util.stream.Collectors.joining;
import static org.glassfish.soteria.cdi.CdiUtils.addAnnotatedTypes;
import static org.glassfish.soteria.cdi.CdiUtils.getAnnotation;
import static org.glassfish.soteria.cdi.CdiUtils.getBeanReference;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.context.Dependent;
import jakarta.enterprise.event.Observes;
import jakarta.enterprise.inject.Any;
import jakarta.enterprise.inject.Default;
import jakarta.enterprise.inject.spi.AfterBeanDiscovery;
import jakarta.enterprise.inject.spi.Annotated;
import jakarta.enterprise.inject.spi.Bean;
import jakarta.enterprise.inject.spi.BeanManager;
import jakarta.enterprise.inject.spi.BeforeBeanDiscovery;
import jakarta.enterprise.inject.spi.DefinitionException;
import jakarta.enterprise.inject.spi.Extension;
import jakarta.enterprise.inject.spi.ProcessBean;
import jakarta.security.enterprise.authentication.mechanism.http.AutoApplySession;
import jakarta.security.enterprise.authentication.mechanism.http.BasicAuthenticationMechanismDefinition;
import jakarta.security.enterprise.authentication.mechanism.http.CustomFormAuthenticationMechanismDefinition;
import jakarta.security.enterprise.authentication.mechanism.http.FormAuthenticationMechanismDefinition;
import jakarta.security.enterprise.authentication.mechanism.http.HttpAuthenticationMechanism;
import jakarta.security.enterprise.authentication.mechanism.http.HttpAuthenticationMechanismHandler;
import jakarta.security.enterprise.authentication.mechanism.http.LoginToContinue;
import jakarta.security.enterprise.authentication.mechanism.http.OpenIdAuthenticationMechanismDefinition;
import jakarta.security.enterprise.authentication.mechanism.http.RememberMe;
import jakarta.security.enterprise.identitystore.DatabaseIdentityStoreDefinition;
import jakarta.security.enterprise.identitystore.IdentityStore;
import jakarta.security.enterprise.identitystore.IdentityStoreHandler;
import jakarta.security.enterprise.identitystore.InMemoryIdentityStoreDefinition;
import jakarta.security.enterprise.identitystore.LdapIdentityStoreDefinition;
import java.lang.annotation.Annotation;
import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import org.glassfish.soteria.SecurityContextImpl;
import org.glassfish.soteria.SoteriaServiceProviders;
import org.glassfish.soteria.Utils;
import org.glassfish.soteria.cdi.spi.BeanDecorator;
import org.glassfish.soteria.cdi.spi.WebXmlLoginConfig;
import org.glassfish.soteria.identitystores.DatabaseIdentityStore;
import org.glassfish.soteria.identitystores.InMemoryIdentityStore;
import org.glassfish.soteria.identitystores.LdapIdentityStore;
import org.glassfish.soteria.identitystores.hash.Pbkdf2PasswordHashImpl;
import org.glassfish.soteria.mechanisms.BasicAuthenticationMechanism;
import org.glassfish.soteria.mechanisms.CustomFormAuthenticationMechanism;
import org.glassfish.soteria.mechanisms.DefaultHttpAuthenticationMechanismHandler;
import org.glassfish.soteria.mechanisms.FormAuthenticationMechanism;
import org.glassfish.soteria.mechanisms.OpenIdAuthenticationMechanism;
import org.glassfish.soteria.mechanisms.openid.OpenIdIdentityStore;
import org.glassfish.soteria.mechanisms.openid.controller.AuthenticationController;
import org.glassfish.soteria.mechanisms.openid.controller.ConfigurationController;
import org.glassfish.soteria.mechanisms.openid.controller.JWTValidator;
import org.glassfish.soteria.mechanisms.openid.controller.NonceController;
import org.glassfish.soteria.mechanisms.openid.controller.ProviderMetadataController;
import org.glassfish.soteria.mechanisms.openid.controller.StateController;
import org.glassfish.soteria.mechanisms.openid.controller.TokenController;
import org.glassfish.soteria.mechanisms.openid.controller.UserInfoController;
import org.glassfish.soteria.mechanisms.openid.domain.OpenIdContextImpl;

public class CdiExtension implements Extension {

    private static final Logger LOGGER = Logger.getLogger(CdiExtension.class.getName());

    private List<Bean<IdentityStore>> identityStoreBeans = new ArrayList<>();
    private List<Bean<HttpAuthenticationMechanism>> authenticationMechanismBeans = new ArrayList<>();
    private List<Bean<?>> extraBeans = new ArrayList<>();

    private boolean httpAuthenticationMechanismFound;

    public void register(@Observes BeforeBeanDiscovery beforeBean, BeanManager beanManager) {
        addAnnotatedTypes(beforeBean, beanManager,
            AutoApplySessionInterceptor.class,
            RememberMeInterceptor.class,
            LoginToContinueInterceptor.class,
            FormAuthenticationMechanism.class,
            CustomFormAuthenticationMechanism.class,
            SecurityContextImpl.class,
            IdentityStoreHandler.class,
            Pbkdf2PasswordHashImpl.class,

            // OpenID types
            AuthenticationController.class,
            ConfigurationController.class,
            NonceController.class,
            ProviderMetadataController.class,
            StateController.class,
            TokenController.class,
            UserInfoController.class,
            OpenIdContextImpl.class,
            OpenIdIdentityStore.class,
            OpenIdAuthenticationMechanism.class,
            JWTValidator.class
        );
    }

    public <T> void processBean(@Observes ProcessBean<T> eventIn, BeanManager beanManager) {
        ProcessBean<T> event = eventIn; // JDK8 u60 workaround
        Class<?> beanClass = event.getBean().getBeanClass();

        Optional<InMemoryIdentityStoreDefinition> optionalInMemoryStore = getAnnotation(beanManager, event.getAnnotated(), InMemoryIdentityStoreDefinition.class);
        optionalInMemoryStore.ifPresent(inMemoryIdentityStoreDefinition -> {
            logActivatedIdentityStore(InMemoryIdentityStore.class, beanClass);

            identityStoreBeans.add(new CdiProducer<IdentityStore>()
                    .scope(ApplicationScoped.class)
                    .types(Object.class, IdentityStore.class, InMemoryIdentityStore.class)
                    .addToId(InMemoryIdentityStoreDefinition.class)
                    .create(e -> new InMemoryIdentityStore(inMemoryIdentityStoreDefinition))
            );
        });

        Optional<DatabaseIdentityStoreDefinition> optionalDBStore = getAnnotation(beanManager, event.getAnnotated(), DatabaseIdentityStoreDefinition.class);
        optionalDBStore.ifPresent(dataBaseIdentityStoreDefinition -> {
            logActivatedIdentityStore(DatabaseIdentityStoreDefinition.class, beanClass);

            identityStoreBeans.add(new CdiProducer<IdentityStore>()
                    .scope(ApplicationScoped.class)
                    .types(Object.class, IdentityStore.class, DatabaseIdentityStore.class)
                    .addToId(DatabaseIdentityStoreDefinition.class)
                    .create(e -> new DatabaseIdentityStore(
                        DatabaseIdentityStoreDefinitionAnnotationLiteral.eval(
                            dataBaseIdentityStoreDefinition)))
            );
        });

        Optional<LdapIdentityStoreDefinition> optionalLdapStore = getAnnotation(beanManager, event.getAnnotated(), LdapIdentityStoreDefinition.class);
        optionalLdapStore.ifPresent(ldapIdentityStoreDefinition -> {
            logActivatedIdentityStore(LdapIdentityStoreDefinition.class, beanClass);

            identityStoreBeans.add(new CdiProducer<IdentityStore>()
                    .scope(ApplicationScoped.class)
                    .types(Object.class, IdentityStore.class, LdapIdentityStore.class)
                    .addToId(LdapIdentityStoreDefinition.class)
                    .create(e -> new LdapIdentityStore(
                        LdapIdentityStoreDefinitionAnnotationLiteral.eval(
                            ldapIdentityStoreDefinition)))
            );
        });


        // BasicAuthenticationMechanism

        getAnnotation(beanManager, event.getAnnotated(), BasicAuthenticationMechanismDefinition.List.class)
            .ifPresent(list -> {
                for (var basicAuthenticationMechanismDefinition : list.value()) {
                    createBasicAuthenticationMechanismBean(basicAuthenticationMechanismDefinition, beanClass);
                }
        });

        getAnnotation(beanManager, event.getAnnotated(), BasicAuthenticationMechanismDefinition.class)
            .ifPresent(basicAuthenticationMechanismDefinition -> {
                createBasicAuthenticationMechanismBean(basicAuthenticationMechanismDefinition, beanClass);
        });


        // FormAuthenticationMechanism

        getAnnotation(beanManager, event.getAnnotated(), FormAuthenticationMechanismDefinition.List.class)
        .ifPresent(list -> {
            for (var formAuthenticationMechanismDefinition : list.value()) {
                createFormAuthenticationMechanismBean(formAuthenticationMechanismDefinition, beanClass);
            }
        });

        getAnnotation(beanManager, event.getAnnotated(), FormAuthenticationMechanismDefinition.class)
            .ifPresent(formAuthenticationMechanismDefinition -> {
                createFormAuthenticationMechanismBean(formAuthenticationMechanismDefinition, beanClass);
        });


        // CustomFormAuthenticationMechanism

        getAnnotation(beanManager, event.getAnnotated(), CustomFormAuthenticationMechanismDefinition.List.class)
        .ifPresent(list -> {
            for (var customFormAuthenticationMechanismDefinition : list.value()) {
                createCustomFormAuthenticationMechanismBean(customFormAuthenticationMechanismDefinition, beanClass);
            }
        });

        getAnnotation(beanManager, event.getAnnotated(), CustomFormAuthenticationMechanismDefinition.class)
            .ifPresent(customFormAuthenticationMechanismDefinition -> {
                createCustomFormAuthenticationMechanismBean(customFormAuthenticationMechanismDefinition, beanClass);
        });

        Optional<OpenIdAuthenticationMechanismDefinition> opentionalOpenIdMechanism = getAnnotation(beanManager, event.getAnnotated(), OpenIdAuthenticationMechanismDefinition.class);
        opentionalOpenIdMechanism.ifPresent(definition -> {
            logActivatedAuthenticationMechanism(OpenIdAuthenticationMechanismDefinition.class, beanClass);

            validateOpenIdParametersFormat(definition);

            authenticationMechanismBeans.add(new CdiProducer<HttpAuthenticationMechanism>()
                    .scope(ApplicationScoped.class)
                    .types(HttpAuthenticationMechanism.class)
                    .qualifiers(createAnnotationInstances(definition.qualifiers()))
                    .addToId(OpenIdAuthenticationMechanism.class)
                    .create(e -> getBeanReference(OpenIdAuthenticationMechanism.class)));

            identityStoreBeans.add(new CdiProducer<IdentityStore>()
                    .scope(ApplicationScoped.class)
                    .types(IdentityStore.class)
                    .addToId(OpenIdIdentityStore.class)
                    .create(e -> getBeanReference(OpenIdIdentityStore.class))
            );

            extraBeans.add(new CdiProducer<OpenIdAuthenticationMechanismDefinition>()
                    .scope(ApplicationScoped.class)
                    .types(OpenIdAuthenticationMechanismDefinition.class)
                    .addToId("OpenId Definition")
                    .create(e -> definition)
            );
        });



        if (event.getBean().getTypes().contains(HttpAuthenticationMechanism.class)) {
            // enabled bean implementing the HttpAuthenticationMechanism found
            httpAuthenticationMechanismFound = true;
        }

        checkForWrongUseOfInterceptors(event.getAnnotated(), beanClass);
    }

    private void createBasicAuthenticationMechanismBean(BasicAuthenticationMechanismDefinition basicAuthenticationMechanismDefinition, Class<?> beanClass) {
        logActivatedAuthenticationMechanism(BasicAuthenticationMechanismDefinition.class, beanClass);

        authenticationMechanismBeans.add(new CdiProducer<HttpAuthenticationMechanism>()
                .scope(ApplicationScoped.class)
                .types(Object.class, HttpAuthenticationMechanism.class, BasicAuthenticationMechanism.class)
                .qualifiers(createAnnotationInstances(basicAuthenticationMechanismDefinition.qualifiers()))
                .addToId(BasicAuthenticationMechanismDefinition.class + toString(basicAuthenticationMechanismDefinition.qualifiers()))
                .create(e -> new BasicAuthenticationMechanism(
                    BasicAuthenticationMechanismDefinitionAnnotationLiteral.eval(
                        basicAuthenticationMechanismDefinition))));
    }

    private String toString(Class<?>[] qualifiers) {
        return Arrays.stream(qualifiers)
                     .map(Object::toString)
                     .collect(joining(", "));

    }

    private void createFormAuthenticationMechanismBean(FormAuthenticationMechanismDefinition formAuthenticationMechanismDefinition, Class<?> beanClass) {
        logActivatedAuthenticationMechanism(FormAuthenticationMechanismDefinition.class, beanClass);

        authenticationMechanismBeans.add(new CdiProducer<HttpAuthenticationMechanism>()
                .scope(ApplicationScoped.class)
                .types(Object.class, HttpAuthenticationMechanism.class)
                .qualifiers(createAnnotationInstances(formAuthenticationMechanismDefinition.qualifiers()))
                .addToId(FormAuthenticationMechanismDefinition.class)
                .create(e -> {
                    FormAuthenticationMechanism authMethod = CdiUtils.getBeanReference(FormAuthenticationMechanism.class);

                    authMethod.setLoginToContinue(
                        LoginToContinueAnnotationLiteral.eval(formAuthenticationMechanismDefinition.loginToContinue()));

                    return authMethod;
                }));
    }

    private void createCustomFormAuthenticationMechanismBean(CustomFormAuthenticationMechanismDefinition customFormAuthenticationMechanismDefinition, Class<?> beanClass) {
        logActivatedAuthenticationMechanism(CustomFormAuthenticationMechanismDefinition.class, beanClass);

        authenticationMechanismBeans.add(new CdiProducer<HttpAuthenticationMechanism>()
                .scope(ApplicationScoped.class)
                .types(Object.class, HttpAuthenticationMechanism.class)
                .qualifiers(createAnnotationInstances(customFormAuthenticationMechanismDefinition.qualifiers()))
                .addToId(CustomFormAuthenticationMechanismDefinition.class)
                .create(e -> {
                    CustomFormAuthenticationMechanism authMethod = CdiUtils.getBeanReference(CustomFormAuthenticationMechanism.class);

                    authMethod.setLoginToContinue(
                        LoginToContinueAnnotationLiteral.eval(customFormAuthenticationMechanismDefinition.loginToContinue()));

                    return authMethod;
                }));
    }

    private void createOpenIdAuthenticationMechanismBean(OpenIdAuthenticationMechanismDefinition openIdAuthenticationMechanismDefinition, Class<?> beanClass) {

    }


    public void afterBean(final @Observes AfterBeanDiscovery afterBeanDiscovery, BeanManager beanManager) {

       BeanDecorator decorator = SoteriaServiceProviders.getServiceProvider(BeanDecorator.class);
       WebXmlLoginConfig loginConfig = SoteriaServiceProviders.getServiceProvider(WebXmlLoginConfig.class);

       if (!identityStoreBeans.isEmpty()) {
           for (Bean<IdentityStore> identityStoreBean : identityStoreBeans) {
               afterBeanDiscovery.addBean(decorator.decorateBean(identityStoreBean, IdentityStore.class, beanManager));
           }
       }

        if (authenticationMechanismBeans.isEmpty() && loginConfig.getAuthMethod() != null) {

            if ("basic".equalsIgnoreCase(loginConfig.getAuthMethod())) {
                authenticationMechanismBeans.add(new CdiProducer<HttpAuthenticationMechanism>()
                    .scope(ApplicationScoped.class)
                    .types(Object.class, HttpAuthenticationMechanism.class, BasicAuthenticationMechanism.class)
                    .addToId(BasicAuthenticationMechanismDefinition.class)
                    .create(e ->
                        new BasicAuthenticationMechanism(
                            new BasicAuthenticationMechanismDefinitionAnnotationLiteral(loginConfig.getRealmName()))));

                httpAuthenticationMechanismFound = true;
            } else if ("form".equalsIgnoreCase(loginConfig.getAuthMethod())) {
                authenticationMechanismBeans.add(new CdiProducer<HttpAuthenticationMechanism>()
                        .scope(ApplicationScoped.class)
                        .types(Object.class, HttpAuthenticationMechanism.class)
                        .addToId(FormAuthenticationMechanismDefinition.class)
                        .create(e -> {
                            FormAuthenticationMechanism authMethod = CdiUtils.getBeanReference(FormAuthenticationMechanism.class);

                            authMethod.setLoginToContinue(
                                new LoginToContinueAnnotationLiteral(
                                    loginConfig.getFormLoginPage(),
                                    true, null,
                                    loginConfig.getFormErrorPage())
                                );

                            return authMethod;
                        }));
                httpAuthenticationMechanismFound = true;
            }
        }

        if (!authenticationMechanismBeans.isEmpty()) {
            for (Bean<HttpAuthenticationMechanism> authenticationMechanismBean : authenticationMechanismBeans) {
                afterBeanDiscovery.addBean(decorator.decorateBean(authenticationMechanismBean, HttpAuthenticationMechanism.class, beanManager));
            }
        }

        for (Bean<?> bean : extraBeans) {
            afterBeanDiscovery.addBean(bean);
        }

        if (extraBeans.isEmpty()) {
            // Publish empty definition to prevent injection errors. The helper components will not work, but
            // will not cause definition error. This is quite unlucky situation, but when definition is on an
            // alternative bean we don't know before this moment whether the bean is enabled or not.

            // Probably can circumvent this using programmatic lookup or Instance injection
            afterBeanDiscovery.addBean()
                .scope(Dependent.class)
                .types(OpenIdAuthenticationMechanismDefinition.class)
                .id("Null OpenId Definition")
                .createWith(cc -> null);
        }

        afterBeanDiscovery.addBean(
            decorator.decorateBean(
                new CdiProducer<IdentityStoreHandler>()
                    .scope(ApplicationScoped.class)
                    .types(Object.class, IdentityStoreHandler.class)
                    .addToId(IdentityStoreHandler.class)
                    .create(e -> {
                        DefaultIdentityStoreHandler defaultIdentityStoreHandler = new DefaultIdentityStoreHandler();
                        defaultIdentityStoreHandler.init();
                        return defaultIdentityStoreHandler;
                    }),
                IdentityStoreHandler.class,
                beanManager));

        afterBeanDiscovery.addBean(
                decorator.decorateBean(
                    new CdiProducer<HttpAuthenticationMechanismHandler>()
                        .scope(ApplicationScoped.class)
                        .types(Object.class, HttpAuthenticationMechanismHandler.class)
                        .addToId(IdentityStoreHandler.class)
                        .create(e -> {
                            DefaultHttpAuthenticationMechanismHandler defaultHttpAuthenticationMechanismHandler = new DefaultHttpAuthenticationMechanismHandler();
                            defaultHttpAuthenticationMechanismHandler.init();
                            return defaultHttpAuthenticationMechanismHandler;
                        }),
                    HttpAuthenticationMechanismHandler.class,
                    beanManager));
    }

    public boolean isHttpAuthenticationMechanismFound() {
        return httpAuthenticationMechanismFound;
    }

    private Annotation[] createAnnotationInstances(Class<?>... types) {
        Annotation[] instances = null;

        if (types.length == 0) {
            instances = (Annotation[]) Array.newInstance(Annotation.class, 2);
            instances[0] = Default.Literal.INSTANCE;
            instances[1] = Any.Literal.INSTANCE;

            return instances;
        }

        instances = Utils.createAnnotationInstances(types);

        if (!containsAny(types)) {
            Annotation[] instancesNew = (Annotation[]) Array.newInstance(Annotation.class, types.length + 1);
            System.arraycopy(instances, 0, instancesNew, 0, instances.length);
            instances = instancesNew;

            instances[types.length] = Any.Literal.INSTANCE;
        }

        return instances;
    }

    private boolean containsAny(Class<?>... types) {
        for (Class<?> type : types) {
            if (type.equals(Any.class)) {
                return true;
            }
        }

        return false;
    }

    private void logActivatedIdentityStore(Class<?> identityStoreClass, Class<?> beanClass) {
        LOGGER.log(Level.INFO, "Activating {0} identity store from {1} class", new Object[]{identityStoreClass.getName(), beanClass.getName()});
    }

    private void logActivatedAuthenticationMechanism(Class<?> authenticationMechanismClass, Class<?> beanClass) {
        LOGGER.log(Level.INFO, "Activating {0} authentication mechanism from {1} class", new Object[]{authenticationMechanismClass.getName(), beanClass.getName()});
    }

    private void checkForWrongUseOfInterceptors(Annotated annotated, Class<?> beanClass) {
        List<Class<? extends Annotation>> annotations = Arrays.asList(AutoApplySession.class, LoginToContinue.class, RememberMe.class);

        for (Class<? extends Annotation> annotation : annotations) {
            // Check if the class is not an interceptor, and is not a valid class to be intercepted.
            if (annotated.isAnnotationPresent(annotation)
                    && !annotated.isAnnotationPresent(jakarta.interceptor.Interceptor.class)
                    && !HttpAuthenticationMechanism.class.isAssignableFrom(beanClass)) {
                LOGGER.log(Level.WARNING, "Only classes implementing {0} may be annotated with {1}. {2} is annotated, but the interceptor won't take effect on it.", new Object[]{
                    HttpAuthenticationMechanism.class.getName(),
                    annotation.getName(),
                    beanClass.getName()});
            }
        }
    }

    private void validateOpenIdParametersFormat(OpenIdAuthenticationMechanismDefinition definition) {
        for (String extraParameter : definition.extraParameters()) {
            String[] parts = extraParameter.split("=");
            if (parts.length != 2) {
                throw new DefinitionException(
                        OpenIdAuthenticationMechanismDefinition.class.getSimpleName()
                                + ".extraParameters() value '" + extraParameter
                                + "' is not of the format key=value"
                );
            }
        }
    }
}
