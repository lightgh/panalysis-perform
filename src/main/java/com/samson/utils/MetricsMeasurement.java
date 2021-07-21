package com.samson.utils;

/**
 * @author - Chinaka .I. Light <ichinaka@byteworks.com.ng>
 * Date: 21/07/2021
 */
public class MetricsMeasurement {

    private long beforeUsedMemory;
    private long startTime, stopTime, timeDifference;
    private long afterUsedMemory;
    private long actualMemoryUsed;

    private MetricsMeasurement(){
        start();
    }

    public static MetricsMeasurement startMM(){
        return new MetricsMeasurement().start();
    }

    private MetricsMeasurement start(){
        startTime = System.nanoTime();
        beforeUsedMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
        return this;
    }

    public MetricsMeasurement stop(){
        this.stopTime = System.nanoTime();
        this.afterUsedMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
        this.actualMemoryUsed = afterUsedMemory - beforeUsedMemory;
        this.timeDifference = stopTime - startTime;
        return this;
    }

    public long getTimeDifference(){
        return timeDifference;
    }

    public long getMemoryUsed(){
        return actualMemoryUsed;
    }

    public long getStartTime(){
        return startTime;
    }

    public long getStopTime(){
        return stopTime;
    }

}
