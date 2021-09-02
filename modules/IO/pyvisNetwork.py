from pyvis.network import Network
import pandas as pd


def show_html(csvpath):
    got_net = Network(height='900px', width='100%', bgcolor='#222222', font_color='white')

    # set the physics layout of the network
    got_net.barnes_hut()
    # got_data = pd.read_csv('../../test/test.csv')
    got_data = pd.read_csv(csvpath)


    sources = got_data['Source']
    targets = got_data['Target']
    weights = got_data['Weight']

    edge_data = zip(sources, targets, weights)

    for e in edge_data:
        src = e[0]
        dst = e[1]
        w = e[2]

        got_net.add_node(src, src, title=src)
        got_net.add_node(dst, dst, title=dst)
        got_net.add_edge(src, dst, value=w)

    neighbor_map = got_net.get_adj_list()

    # add neighbor data to node hover data
    for node in got_net.nodes:
        node['title'] += ' Neighbors:<br>' + '<br>'.join(neighbor_map[node['id']])
        node['value'] = len(neighbor_map[node['id']])

    got_net.show('demo.html')


if __name__ == '__main__':
    show_html('../../test/test.csv')