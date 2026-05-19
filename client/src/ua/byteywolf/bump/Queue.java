package ua.byteywolf.bump;
import java.util.Vector;

public class Queue {
    private Vector vec = new Vector();

    public synchronized void enqueue(Object o) {
        vec.addElement(o);
        this.notifyAll();
    }

    public synchronized Object dequeue() {
        while (vec.size() == 0) {
            try {
                this.wait();
            } catch (InterruptedException e) {
                return null; 
            }
        }
        
        Object o = vec.elementAt(0);
        vec.removeElementAt(0);
        return o;
    }

    public synchronized boolean isEmpty() {
        return vec.size() == 0;
    }

    public synchronized int size() {
        return vec.size();
    }
}