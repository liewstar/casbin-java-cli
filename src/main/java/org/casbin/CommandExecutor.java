package org.casbin;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.casbin.jcasbin.main.EnforceResult;
import org.casbin.jcasbin.main.Enforcer;
import org.casbin.resp.ResponseBody;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Type;
import java.util.*;

public class CommandExecutor {

    private NewEnforcer enforcer;

    private String inputMethodName;

    private String[]  inputVal;

    public CommandExecutor(NewEnforcer enforcer, String inputMethodName, String[] inputVal) {
        this.enforcer = enforcer;
        this.inputMethodName = inputMethodName;
        this.inputVal = inputVal;
    }

    public String outputResult() throws InvocationTargetException, IllegalAccessException, JsonProcessingException {
        Class<? extends Enforcer> clazz = enforcer.getClass();
        Method[] methods = clazz.getMethods();
        //Remove overloaded methods (with List parameters)
        methods = filterOverloadedMethods(methods);
        ResponseBody responseBody = new ResponseBody(null, null);
        for (Method method : methods) {
            String methodName = method.getName();
            if(methodName.equals(inputMethodName)) {
                Type[] genericParameterTypes = method.getGenericParameterTypes();
                Object[] convertedParams = new Object[genericParameterTypes.length];
                Class<?> returnType = method.getReturnType();

                for (int i = 0; i < genericParameterTypes.length; i++) {
                    //String ... -> String[]
                    //String[][] -> String[][]
                    //List<List<String>> -> java.util.List<java.util.List<java.lang.String>>
                    //List<String> -> java.util.List<java.lang.String>
                    if(genericParameterTypes[i] == String.class) {
                        convertedParams[i] = inputVal[i];
                    } else if(genericParameterTypes[i] == Object[].class || genericParameterTypes[i] == String[].class) {
                        convertedParams[i] = Arrays.copyOfRange(inputVal, i, inputVal.length);
                    } else if (genericParameterTypes[i] == String[][].class) {

                    } else if (genericParameterTypes[i].getTypeName().equals("java.util.List<java.lang.String>")) {

                    } else if (genericParameterTypes[i].getTypeName().equals("java.util.List<java.util.List<java.lang.String>>")) {

                    }
                }

                Object invoke = method.invoke(enforcer, convertedParams);
                System.out.println(returnType.getTypeName());
                if(returnType == boolean.class) {
                    responseBody.setAllow((Boolean) invoke);
                } else if (returnType == List.class) {
                    responseBody.setExplain((ArrayList<?>) invoke);
                } else if (returnType == EnforceResult.class) {
                    responseBody.setAllow(((EnforceResult) invoke).isAllow());
                    responseBody.setExplain((ArrayList<?>) ((EnforceResult) invoke).getExplain());
                }
                enforcer.savePolicy();
            }
        }
        ObjectMapper mapper = new ObjectMapper();
        return mapper.writeValueAsString(responseBody);
    }

    public  Method[] filterOverloadedMethods(Method[] methods) {
        List<Method> filteredMethods = new ArrayList<>();

        for (Method method : methods) {
            if (containsList(method.getParameterTypes()) && hasOverload(method, methods)) continue;
            filteredMethods.add(method);
        }

        return filteredMethods.toArray(new Method[0]);
    }

    private boolean containsList(Class<?>[] parameterTypes) {
        for (Class<?> parameterType : parameterTypes) {
            if (parameterType.equals(List.class) || parameterType.isAssignableFrom(List.class)) {
                return true;
            }
        }
        return false;
    }

    private boolean hasOverload(Method method, Method[] methods) {
        String methodName = method.getName();
        Class<?>[] paramTypes = method.getParameterTypes();

        for (Method m : methods) {
            if (m.getName().equals(methodName) && !Arrays.equals(m.getParameterTypes(), paramTypes)) {
                return true;
            }
        }
        return false;
    }
}
