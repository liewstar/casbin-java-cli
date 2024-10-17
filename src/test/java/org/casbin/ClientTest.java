package org.casbin;

import org.apache.commons.cli.ParseException;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class ClientTest {

    @Test
    public void testRBAC() throws ParseException {
        assertEquals(Client.run(new String[]{"enforce","-m","examples/rbac_model.conf","-p","examples/rbac_policy.csv", "alice", "data1", "read"}), "{\"allow\":true,\"explain\":null}");
        assertEquals(Client.run(new String[]{"enforce","-m","examples/rbac_model.conf","-p","examples/rbac_policy.csv", "alice", "data1", "write"}), "{\"allow\":false,\"explain\":null}");
        assertEquals(Client.run(new String[]{"enforce","-m","examples/rbac_model.conf","-p","examples/rbac_policy.csv", "alice", "data2", "read"}), "{\"allow\":true,\"explain\":null}");
        assertEquals(Client.run(new String[]{"enforce","-m","examples/rbac_model.conf","-p","examples/rbac_policy.csv", "alice", "data2", "write"}), "{\"allow\":true,\"explain\":null}");
        assertEquals(Client.run(new String[]{"enforce","-m","examples/rbac_model.conf","-p","examples/rbac_policy.csv", "bob", "data1", "read"}), "{\"allow\":false,\"explain\":null}");
        assertEquals(Client.run(new String[]{"enforce","-m","examples/rbac_model.conf","-p","examples/rbac_policy.csv", "bob", "data1", "write"}), "{\"allow\":false,\"explain\":null}");
        assertEquals(Client.run(new String[]{"enforce","-m","examples/rbac_model.conf","-p","examples/rbac_policy.csv", "bob", "data2", "read"}), "{\"allow\":false,\"explain\":null}");
        assertEquals(Client.run(new String[]{"enforce","-m","examples/rbac_model.conf","-p","examples/rbac_policy.csv", "bob", "data2", "write"}), "{\"allow\":true,\"explain\":null}");
    }

    @Test
    public void testABAC() throws ParseException {
        assertEquals(Client.run(new String[]{"enforce","-m","examples/abac_rule_with_domains_model.conf","-p","examples/abac_rule_with_domains_policy.csv", "alice", "domain1", "data1", "read"}), "{\"allow\":true,\"explain\":null}");
        assertEquals(Client.run(new String[]{"enforce","-m","examples/abac_rule_with_domains_model.conf","-p","examples/abac_rule_with_domains_policy.csv", "alice","domain1", "data1", "write"}), "{\"allow\":true,\"explain\":null}");
        assertEquals(Client.run(new String[]{"enforce","-m","examples/abac_rule_with_domains_model.conf","-p","examples/abac_rule_with_domains_policy.csv", "alice", "domain2", "data1", "read"}), "{\"allow\":false,\"explain\":null}");
        assertEquals(Client.run(new String[]{"enforce","-m","examples/abac_rule_with_domains_model.conf","-p","examples/abac_rule_with_domains_policy.csv", "alice", "domain2", "data1", "write"}), "{\"allow\":false,\"explain\":null}");
        assertEquals(Client.run(new String[]{"enforce","-m","examples/abac_rule_with_domains_model.conf","-p","examples/abac_rule_with_domains_policy.csv", "bob", "domain1", "data2", "read"}), "{\"allow\":false,\"explain\":null}");
        assertEquals(Client.run(new String[]{"enforce","-m","examples/abac_rule_with_domains_model.conf","-p","examples/abac_rule_with_domains_policy.csv", "bob", "domain1", "data2", "write"}), "{\"allow\":false,\"explain\":null}");
        assertEquals(Client.run(new String[]{"enforce","-m","examples/abac_rule_with_domains_model.conf","-p","examples/abac_rule_with_domains_policy.csv", "bob", "domain2", "data2", "read"}), "{\"allow\":true,\"explain\":null}");
        assertEquals(Client.run(new String[]{"enforce","-m","examples/abac_rule_with_domains_model.conf","-p","examples/abac_rule_with_domains_policy.csv", "bob", "domain2", "data2", "read"}), "{\"allow\":true,\"explain\":null}");

    }

    @Test
    public void testAddAndRemovePolicy() throws ParseException {
        assertEquals(Client.run(new String[]{"addPolicy","-m","examples/abac_rule_with_domains_model.conf","-p","examples/abac_rule_with_domains_policy.csv", "alice", "domain1", "data1", "read"}), "{\"allow\":true,\"explain\":null}");
        assertEquals(Client.run(new String[]{"removePolicy","-m","examples/abac_rule_with_domains_model.conf","-p","examples/abac_rule_with_domains_policy.csv", "alice", "domain1", "data1", "read"}), "{\"allow\":true,\"explain\":null}");

        assertEquals(Client.run(new String[]{"addPolicy","-m","examples/rbac_model.conf","-p","examples/rbac_policy.csv", "alice", "data2", "write"}), "{\"allow\":true,\"explain\":null}");
        assertEquals(Client.run(new String[]{"removePolicy","-m","examples/rbac_model.conf","-p","examples/rbac_policy.csv", "alice", "data2", "write"}), "{\"allow\":true,\"explain\":null}");
    }

    @Test
    public void testParseString() {
        String model = "[request_definition]\n" +
                "r = sub, obj, act\n" +
                "\n" +
                "[policy_definition]\n" +
                "p = sub, obj, act\n" +
                "\n" +
                "[role_definition]\n" +
                "g = _, _\n" +
                "\n" +
                "[policy_effect]\n" +
                "e = some(where (p.eft == allow))\n" +
                "\n" +
                "[matchers]\n" +
                "m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act";
        String policy = "p, alice, data1, read\n" +
                "p, bob, data2, write\n" +
                "p, data2_admin, data2, read\n" +
                "p, data2_admin, data2, write\n" +
                "g, alice, data2_admin";
        assertEquals(Client.run(new String[]{"enforce", "-m", model, "-p", policy, "alice", "data1", "read"}), "{\"allow\":true,\"explain\":null}");
    }

    @Test
    public void testCustomFunction() throws ParseException {
        String methodName = "keyMatchTest";
        String model = "[request_definition]\n" +
                "r = sub, obj, act\n" +
                "\n" +
                "[policy_definition]\n" +
                "p = sub, obj, act\n" +
                "\n" +
                "[policy_effect]\n" +
                "e = some(where (p.eft == allow))\n" +
                "\n" +
                "[matchers]\n" +
                "m = r.sub == p.sub && "+methodName+"(r.obj, p.obj) && regexMatch(r.act, p.act)\n";
        String func = "public static boolean "+methodName+"(String key1, String key2) {\n" +
                "        int i = key2.indexOf('*');\n" +
                "        if (i == -1) {\n" +
                "            return key1.equals(key2);\n" +
                "        }\n" +
                "\n" +
                "        if (key1.length() > i) {\n" +
                "            return key1.substring(0, i).equals(key2.substring(0, i));\n" +
                "        }\n" +
                "        return key1.equals(key2.substring(0, i));\n" +
                "    }";
        assertEquals(Client.run(new String[]{"enforce", "-m", model, "-p", "examples/keymatch_policy.csv", "-AF", func, "alice", "/alice_data/resource1", "GET"}), "{\"allow\":true,\"explain\":null}");
        assertEquals(Client.run(new String[]{"enforce", "-m", model, "-p", "examples/keymatch_policy.csv", "-AF", func,   "alice", "/alice_data/resource1", "POST"}), "{\"allow\":true,\"explain\":null}");
        assertEquals(Client.run(new String[]{"enforce", "-m", model, "-p", "examples/keymatch_policy.csv", "-AF", func,   "alice", "/alice_data/resource2", "GET"}), "{\"allow\":true,\"explain\":null}");
        assertEquals(Client.run(new String[]{"enforce", "-m", model, "-p", "examples/keymatch_policy.csv", "-AF", func,   "alice", "/alice_data/resource2", "POST"}), "{\"allow\":false,\"explain\":null}");
        assertEquals(Client.run(new String[]{"enforce", "-m", model, "-p", "examples/keymatch_policy.csv", "-AF", func,   "alice", "/bob_data/resource1", "GET"}), "{\"allow\":false,\"explain\":null}");
        assertEquals(Client.run(new String[]{"enforce", "-m", model, "-p", "examples/keymatch_policy.csv", "-AF", func,   "alice", "/bob_data/resource1", "POST"}), "{\"allow\":false,\"explain\":null}");
        assertEquals(Client.run(new String[]{"enforce", "-m", model, "-p", "examples/keymatch_policy.csv", "-AF", func,   "alice", "/bob_data/resource2", "GET"}), "{\"allow\":false,\"explain\":null}");
        assertEquals(Client.run(new String[]{"enforce", "-m", model, "-p", "examples/keymatch_policy.csv", "-AF", func,   "alice", "/bob_data/resource2", "POST"}), "{\"allow\":false,\"explain\":null}");

        assertEquals(Client.run(new String[]{"enforce", "-m", model, "-p", "examples/keymatch_policy.csv", "-AF", func,   "bob", "/alice_data/resource1", "GET"}), "{\"allow\":false,\"explain\":null}");
        assertEquals(Client.run(new String[]{"enforce", "-m", model, "-p", "examples/keymatch_policy.csv", "-AF", func,   "bob", "/alice_data/resource1", "POST"}), "{\"allow\":false,\"explain\":null}");
        assertEquals(Client.run(new String[]{"enforce", "-m", model, "-p", "examples/keymatch_policy.csv", "-AF", func,   "bob", "/alice_data/resource2", "GET"}), "{\"allow\":true,\"explain\":null}");
        assertEquals(Client.run(new String[]{"enforce", "-m", model, "-p", "examples/keymatch_policy.csv", "-AF", func,   "bob", "/alice_data/resource2", "POST"}), "{\"allow\":false,\"explain\":null}");
        assertEquals(Client.run(new String[]{"enforce", "-m", model, "-p", "examples/keymatch_policy.csv", "-AF", func,   "bob", "/bob_data/resource1", "GET"}), "{\"allow\":false,\"explain\":null}");
        assertEquals(Client.run(new String[]{"enforce", "-m", model, "-p", "examples/keymatch_policy.csv", "-AF", func,   "bob", "/bob_data/resource1", "POST"}), "{\"allow\":true,\"explain\":null}");
        assertEquals(Client.run(new String[]{"enforce", "-m", model, "-p", "examples/keymatch_policy.csv", "-AF", func,   "bob", "/bob_data/resource2", "GET"}), "{\"allow\":false,\"explain\":null}");
        assertEquals(Client.run(new String[]{"enforce", "-m", model, "-p", "examples/keymatch_policy.csv", "-AF", func,   "bob", "/bob_data/resource2", "POST"}), "{\"allow\":true,\"explain\":null}");

        assertEquals(Client.run(new String[]{"enforce", "-m", model, "-p", "examples/keymatch_policy.csv", "-AF", func,   "cathy", "/cathy_data", "GET"}), "{\"allow\":true,\"explain\":null}");
        assertEquals(Client.run(new String[]{"enforce", "-m", model, "-p", "examples/keymatch_policy.csv", "-AF", func,   "cathy", "/cathy_data", "POST"}), "{\"allow\":true,\"explain\":null}");
        assertEquals(Client.run(new String[]{"enforce", "-m", model, "-p", "examples/keymatch_policy.csv", "-AF", func,   "cathy", "/cathy_data", "DELETE"}), "{\"allow\":false,\"explain\":null}");

        }

        @Test
        public void testEnforce() {
            assertEquals(Client.run(new String[]{"enforce", "-m", "examples/rbac_model.conf", "-p", "examples/rbac_policy.csv", "alice", "data1", "read"}), "{\"allow\":true,\"explain\":null}");
        }

        @Test
        public void allTest() {
            assertEquals(Client.run(new String[]{"getAllSubjects", "-m", "examples/rbac_model.conf", "-p", "examples/rbac_policy.csv", "alice", "data1", "read"}), "{\"allow\":null,\"explain\":[\"alice\",\"bob\",\"data2_admin\"]}");
            assertEquals(Client.run(new String[]{"enforceEx", "-m", "examples/rbac_model.conf", "-p", "examples/rbac_policy.csv", "alice", "data1", "read"}), "{\"allow\":true,\"explain\":[\"alice\",\"data1\",\"read\"]}");

        }

        @Test
        public void testReturnValueIsListNested() {
            assertEquals(Client.run(new String[]{"getGroupingPolicy", "-m", "examples/abac_rule_with_domains_model.conf", "-p", "examples/abac_rule_with_domains_policy.csv", "alice", "data1", "read"}), "{\"allow\":null,\"explain\":[[\"alice\",\"admin\",\"domain1\"],[\"bob\",\"admin\",\"domain2\"]]}");
        }


}
