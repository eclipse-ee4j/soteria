/*
 * Copyright (c) 2021 Contributors to the Eclipse Foundation
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
 * Contributors:
 *   2021 : Payara Foundation and/or its affiliates
 *      Initially authored in Security Connectors
 */
package org.glassfish.soteria.openid;


import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.context.Dependent;
import jakarta.enterprise.event.Observes;
import jakarta.enterprise.inject.spi.*;
import jakarta.security.enterprise.authentication.mechanism.http.HttpAuthenticationMechanism;
import jakarta.security.enterprise.identitystore.IdentityStore;
import jakarta.security.enterprise.identitystore.OpenIdAuthenticationDefinition;
import org.glassfish.soteria.openid.controller.*;
import org.glassfish.soteria.openid.domain.OpenIdContextImpl;

import java.util.logging.Logger;

import static java.util.logging.Level.INFO;

/**
 * Activates {@link OpenIdAuthenticationMechanism} with the
 * {@link OpenIdAuthenticationDefinition} annotation configuration.
 *
 * @author Gaurav Gupta
 * @author Patrik Duditš
 * @author Rudy De Busscher
 *
 */
public class OpenIdExtension implements Extension {

    private static final Logger LOGGER = Logger.getLogger(OpenIdExtension.class.getName());

    private OpenIdAuthenticationDefinition definition;

    protected void registerTypes(@Observes BeforeBeanDiscovery before) {
        registerTypes(before,
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

    private void registerTypes(BeforeBeanDiscovery event, Class<?>... classes) {
        for (Class<?> aClass : classes) {
            event.addAnnotatedType(aClass, aClass.getName());
        }
    }

    /**
     * Find the {@link OpenIdAuthenticationDefinition} annotation and validate.
     */
    protected void findOpenIdDefinitionAnnotation(@Observes @WithAnnotations(OpenIdAuthenticationDefinition.class) ProcessAnnotatedType<?> event) {
        Class<?> beanClass = event.getAnnotatedType().getJavaClass();
        OpenIdAuthenticationDefinition standardDefinition = event.getAnnotatedType().getAnnotation(OpenIdAuthenticationDefinition.class);
        setDefinition(standardDefinition, beanClass);
    }

    private void setDefinition(OpenIdAuthenticationDefinition definition, Class<?> sourceClass) {
        if (this.definition != null) {
            LOGGER.warning("Multiple authentication definition found. Will ignore the definition in " + sourceClass);
            return;
        }
        validateExtraParametersFormat(definition);
        this.definition = definition;
        LOGGER.log(INFO, "Activating OpenID Connect authentication definition from class {0}",
                sourceClass.getName());
    }

    protected void validateExtraParametersFormat(OpenIdAuthenticationDefinition definition) {
        for (String extraParameter : definition.extraParameters()) {
            String[] parts = extraParameter.split("=");
            if (parts.length != 2) {
                throw new DefinitionException(
                        OpenIdAuthenticationDefinition.class.getSimpleName()
                                + ".extraParameters() value '" + extraParameter
                                + "' is not of the format key=value"
                );
            }
        }
    }

    protected void registerDefinition(@Observes AfterBeanDiscovery afterBeanDiscovery, BeanManager beanManager) {

        LOGGER.log(INFO, "AfterBean Discovery {0}",
                definition.getClass().getName());

        if (definition != null) {

            // if definition is active we broaden the type of OpenIdAuthenticationMechanism back to
            // HttpAuthenticationMechanism, so it would be picked up by Jakarta Security.
            afterBeanDiscovery.addBean()
                    .beanClass(HttpAuthenticationMechanism.class)
                    .addType(HttpAuthenticationMechanism.class)
                    .id(OpenIdExtension.class.getName() + "/OpenIdAuthenticationMechanism")
                    .scope(ApplicationScoped.class)
                    .produceWith(in -> in.select(OpenIdAuthenticationMechanism.class).get())
                    .disposeWith((inst, callback) -> callback.destroy(inst));

            afterBeanDiscovery.addBean()
                    .beanClass(IdentityStore.class)
                    .addType(IdentityStore.class)
                    .id(OpenIdExtension.class.getName() + "/OpenIdIdentityStore")
                    .scope(ApplicationScoped.class)
                    .produceWith(in -> in.select(OpenIdIdentityStore.class).get())
                    .disposeWith((inst, callback) -> callback.destroy(inst));

            /*
            afterBeanDiscovery.addBean()
                    .beanClass(OpenIdContextImpl.class)
                    .addType(OpenIdContext.class)
                    .id(OpenIdExtension.class.getName() + "/OpenIdContext")
                    .scope(SessionScoped.class)
                    .produceWith(in -> in.select(OpenIdContextImpl.class).get())
                    .disposeWith((inst, callback) -> callback.destroy(inst));
            */

            afterBeanDiscovery.addBean()
                    .beanClass(OpenIdAuthenticationDefinition.class)
                    .types(OpenIdAuthenticationDefinition.class)
                    .scope(ApplicationScoped.class)
                    .id("OpenId Definition")
                    .createWith(cc -> this.definition);


        } else {
            // Publish empty definition to prevent injection errors. The helper components will not work, but
            // will not cause definition error. This is quite unlucky situation, but when definition is on an
            // alternative bean we don't know before this moment whether the bean is enabled or not.
            afterBeanDiscovery.addBean()
                    .beanClass(OpenIdAuthenticationDefinition.class)
                    .types(OpenIdAuthenticationDefinition.class)
                    .scope(Dependent.class)
                    .id("Null OpenId Definition")
                    .createWith(cc -> null);
        }
    }

}
