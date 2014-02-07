package org.cloudfoundry.identity.uaa.user;

import org.junit.runner.RunWith;
import org.springframework.test.annotation.IfProfileValue;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

@ContextConfiguration("classpath:/test-data-source.xml")
@RunWith(SpringJUnit4ClassRunner.class)
@IfProfileValue(name = "spring.profiles.active", values = { "" , "hsqldb", "test,postgresql", "test,mysql", "test,oracle" })
public class LdapUaaUserDatabaseTests {

}
