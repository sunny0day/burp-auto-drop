package net.bytebutcher.burpautodropextension.gui.listener;

import java.util.List;

public interface TableListener<T> {

    void tableChanged(List<T> objects);

}
